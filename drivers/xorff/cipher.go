package xorff

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/rclone/rclone/fs"
	"github.com/rclone/rclone/fs/accounting"
)

// Errors returned by cipher
var ErrorFileClosed = errors.New("file already closed")

//========================================================
//==============types=====================================

// 使用newCipher函数创建Cipher实例
type Cipher struct {
	dirNameEnc  bool
	fileNameEnc bool
	nameEncoder nameEncoding
	encSuf      string
	xorSuf      string
	bytesOfXOR  int //异或的字节数,0xFF+1
	encSufs     map[string]string
}

// nameEncoding are the encoding methods dealing with   names
type nameEncoding interface {
	EncodeToString(src []byte) string
	DecodeString(s string) ([]byte, error)
}

type ReadSeekCloser interface {
	io.Reader
	io.Seeker
	io.Closer
	fs.RangeSeeker
}

// OpenRangeSeek opens the file handle at the offset with the limit given
type OpenRangeSeek func(ctx context.Context, offset, limit int64) (io.ReadCloser, error)

// 实现了Reader,Closer,Seeker,RangSeeker，需要传入的流支持才可以。
type xorFFer struct {
	mu              sync.Mutex
	oriStream       io.Reader
	c               *Cipher
	buf             []byte
	bufIndex        int
	fileIndex       uint64
	err             error
	eofInBytesofXOR bool
	limit           int64 // limit of bytes to read, -1 for unlimited
	openRS          OpenRangeSeek
}

//==============types=====================================
//========================================================

//======================================================
//========new函数=======================================

func newCipher(dirNameEnc bool, fileNameEnc bool, nameEnc string) (*Cipher, error) {
	encSufs := map[string]string{"url64": ".u64", "rawurl64": ".ru64"} //URLbase64编码后缀//RawURL64Encoding编码后缀
	nameEnc = strings.ToLower(nameEnc)
	encSuf, ok := encSufs[nameEnc]
	if !ok {
		return nil, fmt.Errorf("can't find encoding name: %s", nameEnc)
	}
	c := &Cipher{
		fileNameEnc: fileNameEnc,
		dirNameEnc:  dirNameEnc,
		encSuf:      encSuf,
		xorSuf:      "x",
		bytesOfXOR:  0xFF + 1,
		encSufs:     encSufs,
	}
	c.nameEncoder = c.newNameEncoding(c.encSuf)
	if c.nameEncoder == nil {
		return nil, fmt.Errorf("创建名字编码器时发生错误。")
	}
	return c, nil
}

// NewNameEncoding creates a NameEncoding from a string
// 参数使用后缀而不是编码名称是因为xorff允许同时多种编码，根据文件后缀动态获取解码器。
func (c *Cipher) newNameEncoding(encSuf string) nameEncoding {
	encSuf = strings.ToLower(encSuf)
	switch encSuf {
	case c.encSufs["rawurl64"]:
		return base64.RawURLEncoding
	case c.encSufs["url64"]:
		return base64.URLEncoding
	default:
		return nil
	}
}

func (c *Cipher) newXorFFer(in io.Reader) (*xorFFer, error) {
	fh := &xorFFer{
		oriStream:       in,
		c:               c,
		buf:             make([]byte, c.bytesOfXOR),
		eofInBytesofXOR: false,
		limit:           -1,
		fileIndex:       0,
		bufIndex:        0,
	}
	return fh, nil
}

//========new函数========================================
//======================================================

// 未加密返回""，未编码返回""
func (c *Cipher) parseSuffix(name string) (isEncode string, isXOR string) {
	if strings.HasSuffix(name, "."+c.xorSuf) {
		return "", c.xorSuf
	}
	for _, val := range c.encSufs {
		if strings.HasSuffix(name, val+c.xorSuf) {
			return val, c.xorSuf
		}
		if strings.HasSuffix(name, val) {
			return val, ""
		}
	}
	return "", ""
}

// 分析参数的名字是否编码过，编码过则不再编码。未编码过但是有加密标志则不编码。
// 未编码则返回原值
func (c *Cipher) encPath(in string, dir bool) string {
	//是文件夹且文件夹名不编码
	if dir && !c.dirNameEnc {
		return in
	}
	//是文件且文件夹名、文件名都不编码
	if !dir && !c.fileNameEnc && !c.dirNameEnc {
		return in + "." + c.xorSuf
	}
	names := strings.Split(in, "/")
	n := len(names) - 1
	for i := 0; i <= n; i++ {
		//是文件夹且文件夹名不编码
		if dir && !c.dirNameEnc {
			return in
		}
		//是文件且文件夹名、文件名都不编码
		if !dir && !c.fileNameEnc && !c.dirNameEnc {
			return in + "." + c.xorSuf
		}
		if !c.dirNameEnc && i < n { //文件夹名不编码
			continue
		}
		if i == n && !c.fileNameEnc && !dir { //文件名不编码
			names[i] = names[i] + "." + c.xorSuf
			break
		}
		enc, xor := c.parseSuffix(names[i])
		if enc == "" && xor == "" {
			temp := []byte(names[i])
			for k := 0; k < len(temp); k++ {
				temp[k] = ^temp[k]
			}
			names[i] = c.nameEncoder.EncodeToString(temp) + c.encSuf + c.xorSuf //文件夹名或文件名编码
		}
	}
	return strings.Join(names, "/")
}

// 根据名字的后缀进行解码，未编码的名字不解码返回值为原来的名字
func (c *Cipher) decPath(in string) (string, error) {
	names := strings.Split(in, "/") //不能使用stdencoding，因为有/
	for i := range names {
		isEncode, isXOR := c.parseSuffix(names[i])
		if isEncode == "" && isXOR != "" { //解密时文件名未编码需要去掉后缀
			names[i] = strings.TrimSuffix(names[i], "."+isXOR)
		}
		if isEncode != "" {
			decoder := c.newNameEncoding(isEncode)
			tempName, err := decoder.DecodeString(strings.TrimSuffix(names[i], isEncode+isXOR))
			if err != nil {
				return "", err
			}
			for k := 0; k < len(tempName); k++ {
				tempName[k] = ^tempName[k]
			}
			names[i] = string(tempName)
		}
	}
	return strings.Join(names, "/"), nil
}

//============================================================
//============================================================

// 调用时参数in对应流的游标必须处于0，不然解密会出错。
func (c *Cipher) XorFFData(rc io.Reader) (io.Reader, error) {
	in, wrap := accounting.UnWrap(rc) // unwrap the accounting off the Reader
	out, err := c.newXorFFer(in)
	if err != nil {
		return nil, err
	}
	return wrap(out), nil
}

// DecryptDataSeek decrypts the data stream from offset
// The open function must return a ReadCloser opened to the offset supplied.
// You must use this form of DecryptData if you might want to Seek the file handle
func (c *Cipher) XorFFDataSeek(ctx context.Context, openRS OpenRangeSeek, offset, limit int64) (ReadSeekCloser, error) {
	if openRS == nil {
		return nil, errors.New("传入的openRS参数无效！")
	}
	rc, err := openRS(ctx, offset, limit)
	if err != nil {
		return nil, err
	}
	in, wrap := accounting.UnWrap(rc) // unwrap the accounting off the Reader

	outRC, err := c.newXorFFer(in)
	if err != nil {
		return nil, err
	}
	outRC.openRS = openRS // will be called by fh.RangeSeek
	outRC.limit = limit
	outRC.fileIndex = uint64(offset)
	outRC.bufIndex = int(offset)
	outRSC, isRSC := wrap(outRC).(ReadSeekCloser)
	if !isRSC {
		return nil, errors.New("结果不是ReadSeekCloser")
	}
	return outRSC, nil
}

// Read as per io.Reader
func (fh *xorFFer) Read(p []byte) (n int, err error) {
	fh.mu.Lock()
	defer fh.mu.Unlock()

	if fh.err != nil {
		return 0, fh.err
	}
	if fh.oriStream == nil {
		return 0, errors.New("绑定的原始流不存在！")
	}
	lastFileIndex := fh.fileIndex
	//读满缓冲区（原始流的前bytesOfXOR个字节）除非流大小小于（不是小于等于,因为等于就可以读满，且等于时read并不返回EOF）缓冲区
	//并进行取反。如果流大小小于bytesOfXOR则设置EOF标志。只会被执行一次（执行后要么读满缓冲区要么读完了原始流）
	for retry := 0; fh.fileIndex < uint64(fh.c.bytesOfXOR) && !fh.eofInBytesofXOR; {
		n, err := fh.oriStream.Read(fh.buf[fh.fileIndex:fh.c.bytesOfXOR])
		//fmt.Printf("读取了%v个字节进入缓冲区。", n)
		for i := 0; i < n; i++ {
			fh.buf[int(fh.fileIndex)+i] = ^fh.buf[int(fh.fileIndex)+i]
		}
		fh.fileIndex += uint64(n)
		if err == io.EOF {
			fh.eofInBytesofXOR = true
			break
		}
		if err != nil {
			//重试3次
			retry++
			if retry <= 3 {
				continue
			}
			fmt.Printf("\033[1;37;41m读取文件时出错,读取了%v个字节。%v。\033[0m", fh.fileIndex-lastFileIndex, err)
			return int(fh.fileIndex - lastFileIndex), err
		}
	}
	//将缓冲区数据读出。如果多线程读取同一个流的不同地方时，每个线程会调用XorFFDataSeek，fileIndex会等于offset，但是bufIndex会被设置为0.
	//fh.bufIndex < fh.c.bytesOfXOR会导致读取缓冲区，需要加fh.fileIndex< uint64(fh.c.bytesOfXOR),这样如果文件大于256，第一次读后
	//fileIndex=256将跳过读取缓冲区。<=的话如果offset=256，bufIndex=0则将导致读取整个缓冲区。需要设置bufIndex=fileIndex=offset
	if fh.bufIndex < fh.c.bytesOfXOR {
		//if fh.bufIndex < fh.c.bytesOfXOR && fh.fileIndex < uint64(fh.c.bytesOfXOR) {
		toCopy := int(fh.fileIndex) - fh.bufIndex
		if fh.limit >= 0 && fh.limit < int64(toCopy) {
			toCopy = int(fh.limit)
		}
		n = copy(p, fh.buf[fh.bufIndex:fh.bufIndex+toCopy])
		fh.bufIndex += n
		//fmt.Printf("从缓冲区读出了%v个字节。", n)
		if fh.eofInBytesofXOR && n == toCopy { //如果缓冲区内的数据就是全部流且复制完了需要复制的
			fh.err = io.EOF
			err = io.EOF
		}
	} else {
		//缓冲区读完后直接读原始数据(流的大小大于等于缓冲区，流大小等于缓冲区时EOF从此处读出
		//因为read函数读完数据不会立马返回EOF，还要再读一次才返回EOF和n=0）
		n, err = fh.oriStream.Read(p)
		//fmt.Printf("从原始流读取了%v个字节。", n)
		fh.fileIndex += uint64(n)
		fh.err = err
		if n > int(fh.limit) && fh.limit >= 0 {
			n = int(fh.limit)
		}
		//fmt.Printf("输出了%v个字节。", n)
	}
	if fh.limit >= 0 {
		fh.limit -= int64(n)
		if fh.limit == 0 {
			fh.err = io.EOF
			return n, io.EOF
		}
	}
	return n, err
}

// RangeSeek behaves like a call to Seek(offset int64, whence
// int) with the output wrapped in an io.LimitedReader
// limiting the total length to limit.
// RangeSeek with a limit of < 0 is equivalent to a regular Seek.
func (fh *xorFFer) RangeSeek(ctx context.Context, offset int64, whence int, limit int64) (int64, error) {
	fh.mu.Lock()
	defer fh.mu.Unlock()
	if fh.openRS == nil {
		return 0, errors.New("can't seek - not initialised with newDecrypterSeek")
	}
	if whence != io.SeekStart {
		return 0, errors.New("can only seek from the start")
	}
	// Reset error or return it if not EOF
	if fh.err == io.EOF {
		fh.err = nil
	} else if fh.err != nil {
		return 0, fh.err
	}
	// Can we seek underlying stream directly?
	if oriStream, ok := fh.oriStream.(fs.RangeSeeker); ok {
		// Seek underlying stream directly
		_, err := oriStream.RangeSeek(ctx, offset, 0, limit)
		if err != nil {
			return 0, err
		}
	} else {
		// if not reopen with seek
		oriStreamCloser, isCloser := fh.oriStream.(io.Closer)
		if !isCloser {
			return 0, fmt.Errorf("传入的流不支持close")
		}
		err := oriStreamCloser.Close() // close underlying file
		if err != nil {
			return 0, err
		}
		fh.oriStream = nil
		// Re-open the underlying object with the offset given
		rc, err := fh.openRS(ctx, offset, limit)
		if err != nil {
			return 0, fmt.Errorf("couldn't reopen file with offset and limit: %w", err)
		}
		// Set the file handle
		fh.oriStream = rc
	}
	// Set the limit
	fh.limit = limit
	return offset, nil
}

// Seek implements the io.Seeker interface
func (fh *xorFFer) Seek(offset int64, whence int) (int64, error) {
	//return fh.rc.
	return fh.RangeSeek(context.TODO(), offset, whence, -1)
}

func (fh *xorFFer) Close() error {
	fh.mu.Lock()
	defer fh.mu.Unlock()
	fh.oriStream = nil
	fh.err = ErrorFileClosed
	return nil
}

// check interfaces
var (
	_ io.ReadCloser  = (*xorFFer)(nil)
	_ io.Seeker      = (*xorFFer)(nil)
	_ fs.RangeSeeker = (*xorFFer)(nil)
	_ io.Reader      = (*xorFFer)(nil)
)
