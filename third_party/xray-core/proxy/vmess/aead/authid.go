package aead

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	rand3 "crypto/rand"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"math"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/antireplay"
)

var (
	ErrNotFound = errors.New("user do not exist")
	ErrReplay   = errors.New("replayed request")
)

func CreateAuthID(cmdKey []byte, time int64) [16]byte {
	buf := bytes.NewBuffer(nil)
	common.Must(binary.Write(buf, binary.BigEndian, time))
	var zero uint32
	common.Must2(io.CopyN(buf, rand3.Reader, 4))
	zero = crc32.ChecksumIEEE(buf.Bytes())
	common.Must(binary.Write(buf, binary.BigEndian, zero))
	aesBlock := NewCipherFromKey(cmdKey)
	if buf.Len() != 16 {
		panic("Size unexpected")
	}
	var result [16]byte
	aesBlock.Encrypt(result[:], buf.Bytes())
	return result
}

func NewCipherFromKey(cmdKey []byte) cipher.Block {
	aesBlock, err := aes.NewCipher(KDF16(cmdKey, KDFSaltConstAuthIDEncryptionKey))
	if err != nil {
		panic(err)
	}
	return aesBlock
}

type AuthIDDecoder struct {
	s cipher.Block
}

func NewAuthIDDecoder(cmdKey []byte) *AuthIDDecoder {
	return &AuthIDDecoder{NewCipherFromKey(cmdKey)}
}

func (aidd *AuthIDDecoder) Decode(data, decoded *[16]byte) (int64, uint32, int32, uint32) {
	aidd.s.Decrypt(decoded[:], data[:])
	t := int64(binary.BigEndian.Uint64(decoded[:8]))
	rand := int32(binary.BigEndian.Uint32(decoded[8:12]))
	zero := binary.BigEndian.Uint32(decoded[12:16])
	return t, zero, rand, crc32.ChecksumIEEE(decoded[:12])
}

func NewAuthIDDecoderHolder() *AuthIDDecoderHolder {
	return &AuthIDDecoderHolder{make(map[string]*AuthIDDecoderItem), antireplay.NewExactAuthIDFilter()}
}

type AuthIDDecoderHolder struct {
	decoders map[string]*AuthIDDecoderItem
	filter   *antireplay.ExactAuthIDFilter
}

type AuthIDDecoderItem struct {
	dec    *AuthIDDecoder
	ticket interface{}
}

func NewAuthIDDecoderItem(key [16]byte, ticket interface{}) *AuthIDDecoderItem {
	return &AuthIDDecoderItem{
		dec:    NewAuthIDDecoder(key[:]),
		ticket: ticket,
	}
}

func (a *AuthIDDecoderHolder) AddUser(key [16]byte, ticket interface{}) {
	a.decoders[string(key[:])] = NewAuthIDDecoderItem(key, ticket)
}

func (a *AuthIDDecoderHolder) RemoveUser(key [16]byte) {
	delete(a.decoders, string(key[:]))
}

func (a *AuthIDDecoderHolder) Match(authID [16]byte) (interface{}, error) {
	var decoded [16]byte
	for _, v := range a.decoders {
		t, z, _, checksum := v.dec.Decode(&authID, &decoded)
		if z != checksum {
			continue
		}

		if t < 0 {
			continue
		}

		if !validAuthIDTime(t, time.Now().Unix()) {
			continue
		}

		if !a.filter.Check(authID) {
			return nil, ErrReplay
		}

		return v.ticket, nil
	}
	return nil, ErrNotFound
}

func validAuthIDTime(authIDTime, now int64) bool {
	return authIDTime >= 0 && math.Abs(math.Abs(float64(authIDTime))-float64(now)) <= 120
}
