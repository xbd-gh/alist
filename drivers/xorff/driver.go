package xorff

import (
	"context"
	"errors"
	"fmt"
	"io"
	stdpath "path"
	"strings"

	"github.com/alist-org/alist/v3/internal/driver"
	"github.com/alist-org/alist/v3/internal/errs"
	"github.com/alist-org/alist/v3/internal/fs"
	"github.com/alist-org/alist/v3/internal/model"
	"github.com/alist-org/alist/v3/internal/op"
	"github.com/alist-org/alist/v3/internal/sign"
	"github.com/alist-org/alist/v3/internal/stream"
	"github.com/alist-org/alist/v3/pkg/http_range"
	"github.com/alist-org/alist/v3/pkg/utils"
	"github.com/alist-org/alist/v3/server/common"
	log "github.com/sirupsen/logrus"
)

type Addition struct {
	// Usually one of two
	//driver.RootPath
	//driver.RootID
	// define other

	FileNameEnc  bool   `json:"file_name_enc" required:"true" default:"true" help:"whether encode the file name"`
	DirNameEnc   bool   `json:"dir_name_enc" required:"true" default:"true" help:"whether encode the dir name"`
	RemotePath   string `json:"remote_path" required:"true" help:"This is where the encrypted data stores"` //alist视角下的绝对路径
	NameEncoding string `json:"name_encoding" type:"select" required:"true" options:"URL64,RawURL64" default:"RawURL64" help:"for advanced user only!"`
	Thumbnail    bool   `json:"thumbnail" required:"true" default:"false" help:"enable thumbnail which pre-generated under .thumbnails folder"`
	ShowHidden   bool   `json:"show_hidden"  default:"true" required:"true" help:"show hidden directories and files"`
	ShowInEnc    bool   `json:"show_in_enc"  default:"false" required:"true" help:"show directories and files in enc view"`
}

var config = driver.Config{
	Name:              "XorFS",
	LocalSort:         true,
	OnlyLocal:         false,
	OnlyProxy:         true,
	NoCache:           true,
	NoUpload:          false,
	NeedMs:            false,
	DefaultRoot:       "/",
	CheckStatus:       false,
	Alert:             "",
	NoOverwriteUpload: false,
}

func init() {
	op.RegisterDriver(func() driver.Driver {
		return &XorDriver{}
	})
}

type XorDriver struct {
	model.Storage
	Addition
	cipher *Cipher
	//remoteStorage driver.Driver
	pathMap map[string]string
	pathSep string
}

//===========================================================
//============内部函数========================================

// 参数path为该文件系统xorff下的绝对路径。返回值以/开始末尾没有/
// ""对应的返回值为/
func (d *XorDriver) makePathStd(path string) string {
	for strings.HasSuffix(path, d.pathSep) {
		path = strings.TrimSuffix(path, d.pathSep)
	}
	for strings.HasPrefix(path, d.pathSep) {
		path = strings.TrimPrefix(path, d.pathSep)
	}
	if !strings.HasPrefix(path, d.pathSep) {
		path = d.pathSep + path
	}
	return path
}

// 在d.pathMap中根据xorffPath查找alistPath（原始路径）因为xorff文件系统里的名字可以是编码的也可以是非编码的，
// 需要根据原始对象信息获取真实路径，而不是一律将path进行编码
// fs.get()返回的obj是model.ObjWrapName，obj中的path不是alist视图。所以只能自己组装path
// model.obj也说了ID和Path是driver内部使用的，所以别的driver返回的obj中的ID和Path不能使用
func (d *XorDriver) findAlistPath(ctx context.Context, xorffPath string) (alistPath string, err error) {
	if d.pathMap == nil {
		d.pathMap = make(map[string]string)
		d.pathMap["/"] = d.makePathStd(d.RemotePath)
	}
	xorffPath = d.makePathStd(xorffPath)
	//如果没有找到path则寻找父目录并列出对象加入pathMap，再次寻找。但是/目录例外，/没有父目录。/已经存在于pathMap中了。
	alistPath, isExist := d.pathMap[xorffPath]
	if isExist {
		return alistPath, nil
	}
	n := strings.LastIndex(xorffPath, d.pathSep)
	if n < 0 { //path已经规范化了，必须能找到d.pathSep
		return "", errors.New("bad path! ")
	}
	var pPath string
	if n >= 0 {
		pPath = xorffPath[:n]
		if pPath == "" {
			pPath = d.pathSep
		}
		tPath, err := d.findAlistPath(ctx, pPath) //查找父目录
		if tPath != "" {
			alistPath = tPath
		} else { //父目录找不到则该xorffPath一定找不到
			return "", err
		}
	}
	alistObjs, err := fs.List(ctx, alistPath, &fs.ListArgs{NoLog: true})
	if err != nil && alistObjs == nil {
		return "", err
	}
	for _, obj := range alistObjs {
		xorffObj := d.initXorffObj(ctx, obj)
		if xorffObj == nil {
			log.Warnf("Get name failed for %s ,will skip it.", pPath+obj.GetName())
		} else {
			xPath := stdpath.Join(pPath, xorffObj.Name)
			d.pathMap[d.makePathStd(xPath)] = d.makePathStd(stdpath.Join(alistPath, obj.GetName()))
		}
	}
	//再次寻找
	alistPath, isExist = d.pathMap[xorffPath]
	if isExist {
		return alistPath, nil
	} else {
		return "", errs.ObjectNotFound
	}
}

// 需要判断返回值是否为空,返回值始终以/开始
// 如果obj是XorFF_obj类型则从字段中取值，其它则通过findAlistPath(obj.GetPath())。
// 但是其它类型的path又是内部使用的可能不是真正的路径。alist每次调用driver时应该是使用的driver生成的obj？
func (d *XorDriver) getAlistPath(ctx context.Context, obj model.Obj) string {
	var alistPath string
	switch obj := obj.(type) {
	case *XorFF_obj:
		alistPath = obj.GetAlistPath()
	default:
		tPath, err := d.findAlistPath(ctx, obj.GetPath())
		if err != nil {
			return ""
		}
		alistPath = tPath
	}
	return d.makePathStd(alistPath)
}

// obj为alistObj或者XorFF_obj（没有意义，因为可以直接使用XorFF_obj.isEnc、isXor）。
// 当传入参数为XorFF_obj不能使用返回的结果赋值给同一个XorFF_obj，没有意义。
func (d *XorDriver) parseStatus(ctx context.Context, obj model.Obj) (isEnc bool, isXorFF bool) {
	switch obj := obj.(type) {
	case *XorFF_obj:
		return obj.isEncoded, obj.isXorFF
	default:
		enc, xor := d.cipher.parseSuffix(obj.GetName())
		if enc == "" {
			isEnc = false
		} else {
			isEnc = true
		}
		if xor == "" {
			isXorFF = false
		} else {
			isXorFF = true
		}
		return isEnc, isXorFF
	}
}

// 根据d.ShowInEnc生成XorFF_obj的name，返回的XorFF_obj没有初始化path、alistPath
func (d *XorDriver) initXorffObj(ctx context.Context, alistObj model.Obj) *XorFF_obj {
	xorObj := XorFF_obj{}
	var err error
	xorObj.isEncoded, xorObj.isXorFF = d.parseStatus(ctx, alistObj)
	alistName := alistObj.GetName()
	if d.ShowInEnc {
		if xorObj.isXorFF { //没有只编码不加密的情况
			xorObj.Name = alistName
		} else {
			xorObj.Name = d.cipher.encPath(alistName, alistObj.IsDir())
		}
	} else {
		xorObj.Name, err = d.cipher.decPath(alistName)
		if err != nil {
			return nil
		}
	}
	xorObj.Size = alistObj.GetSize()
	xorObj.Modified = alistObj.ModTime()
	xorObj.IsFolder = alistObj.IsDir()
	xorObj.Ctime = alistObj.CreateTime()
	return &xorObj
}

//============内部函数========================================
//===========================================================

func (d *XorDriver) Config() driver.Config {
	return config
}

func (d *XorDriver) GetAddition() driver.Additional {
	return &d.Addition
}

func (d *XorDriver) Init(ctx context.Context) error {
	if strings.HasPrefix(d.Storage.MountPath, d.RemotePath) {
		return fmt.Errorf("加密目录%s不能位于挂载点%s的上层", d.RemotePath, d.Storage.MountPath)
	}
	obj, err := fs.Get(ctx, d.RemotePath, &fs.GetArgs{NoLog: true})
	if err != nil {
		return err
	}
	if !obj.IsDir() {
		return fmt.Errorf("加密目录%s必须是目录不能是文件。", d.RemotePath)
	}
	d.NameEncoding = utils.GetNoneEmpty(d.NameEncoding, "RawURL64")
	op.MustSaveDriverStorage(d)
	//need remote storage exist
	_, err = fs.GetStorage(d.RemotePath, &fs.GetStoragesArgs{})
	if err != nil {
		return fmt.Errorf("can't find remote storage: %w", err)
	}

	c, err := newCipher(d.DirNameEnc, d.FileNameEnc, d.NameEncoding, d.pathSep)
	if err != nil {
		return fmt.Errorf("failed to create Cipher: %w", err)
	}
	d.cipher = c
	d.pathSep = "/"
	d.pathMap = make(map[string]string)
	d.pathMap["/"] = d.makePathStd(d.RemotePath)
	return nil
}

func (d *XorDriver) Drop(ctx context.Context) error {
	return nil
}

func (d *XorDriver) List(ctx context.Context, dir model.Obj, args model.ListArgs) ([]model.Obj, error) {
	if !dir.IsDir() {
		return nil, fmt.Errorf("not dir!")
	}
	alistPath := d.getAlistPath(ctx, dir)
	if alistPath == "" {
		return nil, errs.ObjectNotFound
	}
	alistObjs, err := fs.List(ctx, alistPath, &fs.ListArgs{NoLog: true})
	if err != nil {
		return nil, err
	}
	var result []model.Obj
	for _, alistObj := range alistObjs {
		// the obj must implement the model.SetPath interface
		xorObj := d.initXorffObj(ctx, alistObj)
		if xorObj == nil {
			continue
		}
		path := d.makePathStd(stdpath.Join(dir.GetPath(), xorObj.Name))
		xorObj.Path = path
		aPath := d.makePathStd(stdpath.Join(alistPath, alistObj.GetName()))
		xorObj.alistPath = aPath
		d.pathMap[path] = aPath //顺便更新pathMap
		if !d.ShowHidden && strings.HasPrefix(xorObj.Name, ".") {
			continue
		}
		if alistObj.IsDir() {
			result = append(result, xorObj)
		} else {
			thumb, ok := model.GetThumb(alistObj)
			if d.Thumbnail && thumb == "" {
				thumbPath := stdpath.Join(args.ReqPath, ".thumbnails", xorObj.Name+".webp")
				thumb = fmt.Sprintf("%s/d%s?sign=%s",
					common.GetApiUrl(common.GetHttpReq(ctx)),
					utils.EncodePath(thumbPath, true),
					sign.Sign(thumbPath))
			}
			if !ok && !d.Thumbnail {
				result = append(result, xorObj)
			} else {
				objWithThumb := model.ObjThumb{
					Object: xorObj.Object,
					Thumbnail: model.Thumbnail{
						Thumbnail: thumb,
					},
				}
				result = append(result, &objWithThumb)
			}
		}
	}
	return result, nil
}

func (d *XorDriver) Get(ctx context.Context, path string) (model.Obj, error) {
	alistPath, err := d.findAlistPath(ctx, path)
	if err != nil {
		return nil, errs.ObjectNotFound
	}
	alistObj, err := fs.Get(ctx, alistPath, &fs.GetArgs{NoLog: true})
	if err != nil {
		return nil, errs.ObjectNotFound
	}
	xorObj := d.initXorffObj(ctx, alistObj)
	if xorObj == nil {
		return nil, errs.ObjectNotFound
	}
	xorObj.Path = path
	xorObj.Name = stdpath.Base(path)
	xorObj.ID = alistObj.GetName()
	xorObj.alistPath = alistPath
	return xorObj, nil
}

func (d *XorDriver) Link(ctx context.Context, file model.Obj, args model.LinkArgs) (*model.Link, error) {
	alistPath := d.getAlistPath(ctx, file)
	if alistPath == "" {
		return nil, errs.ObjectNotFound
	}
	remoteLink, remoteFile, err := fs.Link(ctx, alistPath, args)
	if err != nil {
		return nil, err
	}
	if remoteLink.RangeReadCloser == nil && remoteLink.MFile == nil && len(remoteLink.URL) == 0 {
		return nil, fmt.Errorf("the remote storage driver need to be enhanced to support encrytion")
	}
	_, xor := d.parseStatus(ctx, file)
	if (d.ShowInEnc && xor) || (!d.ShowInEnc && !xor) { //加密视图时文件已经加密 或者 解密视图时文件未加密 则返回原始链接
		return remoteLink, nil
	}
	remoteFileSize := remoteFile.GetSize()
	remoteClosers := utils.EmptyClosers()
	rangeReaderFunc := func(ctx context.Context, underlyingOffset, underlyingLength int64) (io.ReadCloser, error) {
		length := underlyingLength
		if underlyingLength >= 0 && underlyingOffset+underlyingLength >= remoteFileSize {
			length = -1
		}
		rrc := remoteLink.RangeReadCloser
		if len(remoteLink.URL) > 0 {
			var converted, err = stream.GetRangeReadCloserFromLink(remoteFileSize, remoteLink)
			if err != nil {
				return nil, err
			}
			rrc = converted
		}
		if rrc != nil {
			remoteReader, err := rrc.RangeRead(ctx, http_range.Range{Start: underlyingOffset, Length: length})
			remoteClosers.AddClosers(rrc.GetClosers())
			if err != nil {
				return nil, err
			}
			return remoteReader, nil
		}
		if remoteLink.MFile != nil {
			_, err := remoteLink.MFile.Seek(underlyingOffset, io.SeekStart)
			if err != nil {
				return nil, err
			}
			//keep reuse same MFile and close at last.
			remoteClosers.Add(remoteLink.MFile)
			return io.NopCloser(remoteLink.MFile), nil
		}
		return nil, errs.NotSupport
	}
	resultRangeReader := func(ctx context.Context, httpRange http_range.Range) (io.ReadCloser, error) {
		readSeeker, err := d.cipher.XorFFDataSeek(ctx, rangeReaderFunc, httpRange.Start, httpRange.Length)
		if err != nil {
			return nil, err
		}
		return readSeeker, nil
	}
	resultRangeReadCloser := &model.RangeReadCloser{RangeReader: resultRangeReader, Closers: remoteClosers}
	resultLink := &model.Link{
		RangeReadCloser: resultRangeReadCloser,
		Expiration:      remoteLink.Expiration,
	}
	return resultLink, nil
}

func (d *XorDriver) MakeDir(ctx context.Context, parentDir model.Obj, dirName string) error {
	alistPath := d.getAlistPath(ctx, parentDir)
	if alistPath == "" {
		return errs.ObjectNotFound
	}
	var newDirName string
	if d.ShowInEnc {
		newDirName = dirName
	} else {
		newDirName = d.cipher.encPath(dirName, true)
	}
	return fs.MakeDir(ctx, stdpath.Join(alistPath, newDirName))
}

func (d *XorDriver) Move(ctx context.Context, srcObj, dstDir model.Obj) error {
	alistSrcPath := d.getAlistPath(ctx, srcObj)
	if alistSrcPath == "" {
		return errs.ObjectNotFound
	}
	alistDstPath := d.getAlistPath(ctx, dstDir)
	if alistDstPath == "" {
		return errs.ObjectNotFound
	}
	err := fs.Move(ctx, alistSrcPath, alistDstPath)
	if err == nil {
		delete(d.pathMap, srcObj.GetPath())
	}
	return err
}

// 不区分原名字是否编码过，只要rename就按照当前的编码方式进行编码。因为如果想rename后不编码可以去原路径rename。
// 如果按照原名字是否编码而选择是否编码的话，一旦想rename后 是编码的 则无法做到。这样导致名字编码了但是文件未加密。
// 需要改成按照原名字是否编码
func (d *XorDriver) Rename(ctx context.Context, srcObj model.Obj, newName string) error {
	alistPath := d.getAlistPath(ctx, srcObj)
	if alistPath == "" {
		return errs.ObjectNotFound
	}
	var newEncName string
	if d.ShowInEnc {
		//newEncName = newName//原来是编码加密的这样重命名时如果改了后缀会导致编码加密标志丢失
		return errors.New("加密视图模式下不支持重命名！")
	} else {
		_, xor := d.parseStatus(ctx, srcObj)
		if !xor { //没有只编码不加密的情况.只要不加密就判定没有编码
			newEncName = newName
		} else {
			newEncName = d.cipher.encPath(newName, true)
		}
	}
	err := fs.Rename(ctx, alistPath, newEncName)
	if err == nil {
		delete(d.pathMap, srcObj.GetPath())
	}
	return err
}

func (d *XorDriver) Copy(ctx context.Context, srcObj, dstDir model.Obj) error {
	alistSrcPath := d.getAlistPath(ctx, srcObj)
	if alistSrcPath == "" {
		return errs.ObjectNotFound
	}
	alistDstPath := d.getAlistPath(ctx, dstDir)
	if alistDstPath == "" {
		return errs.ObjectNotFound
	}
	_, err := fs.Copy(ctx, alistSrcPath, alistDstPath)
	return err

}

func (d *XorDriver) Remove(ctx context.Context, obj model.Obj) error {
	alistPath := d.getAlistPath(ctx, obj)
	if alistPath == "" {
		return errs.ObjectNotFound
	}
	err := fs.Remove(ctx, alistPath)
	if err == nil {
		delete(d.pathMap, obj.GetPath())
	} //更新d.pathMap
	return err
}

func (d *XorDriver) Put(ctx context.Context, dstDir model.Obj, streamer model.FileStreamer, up driver.UpdateProgress) error {
	alistDstPath := d.getAlistPath(ctx, dstDir)
	if alistDstPath == "" {
		return errs.ObjectNotFound
	}
	fileName := streamer.GetName()
	_, xor := d.cipher.parseSuffix(fileName)
	if (d.ShowInEnc && xor != "") || (!d.ShowInEnc && xor == "") { //加密视图下文件已加密 或者 解密视图文件未加密
		if !d.ShowInEnc && xor == "" { //解密视图文件未加密,不允许出现未加密但是编码的情况
			fileName = d.cipher.encPath(fileName, false)
		} else if d.ShowInEnc && xor != "" { //加密视图下文件已加密
			tName, err := d.cipher.decPath(fileName)
			if err == nil {
				fileName = tName
			}
		}
		wrappedIn, err := d.cipher.XorFFData(streamer)
		if err != nil {
			return fmt.Errorf("failed to EncryptData: %w", err)
		}
		// doesn't support seekableStream, since rapid-upload is not working for encrypted data
		streamOut := &stream.FileStream{
			Obj: &model.Object{
				ID:       streamer.GetID(),
				Path:     streamer.GetPath(),
				Name:     fileName,
				Size:     streamer.GetSize(),
				Modified: streamer.ModTime(),
				IsFolder: streamer.IsDir(),
			},
			Reader:            wrappedIn,
			Mimetype:          "application/octet-stream",
			WebPutAsTask:      streamer.NeedStore(),
			ForceStreamUpload: true,
			Exist:             streamer.GetExist(),
		}
		streamer = streamOut
	}
	return fs.PutDirectly(ctx, alistDstPath, streamer)
}

//func (d *Safe) Other(ctx context.Context, args model.OtherArgs) (interface{}, error) {
//	return nil, errs.NotSupport
//}

var _ driver.Driver = (*XorDriver)(nil)

//=======================================
//=====XorFF_obj=========================

type XorFF_obj struct {
	model.Object
	isEncoded bool
	isXorFF   bool
	alistPath string //存储的是alist视图下的path
}

func (o *XorFF_obj) GetAlistPath() string {
	return o.alistPath
}

func (o *XorFF_obj) GetAlistName() string {
	return stdpath.Base(o.alistPath)
}

//=====XorFF_obj=========================
//=======================================
