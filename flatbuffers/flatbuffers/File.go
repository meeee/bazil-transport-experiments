// automatically generated, do not modify

package flatbuffers

import (
	flatbuffers "github.com/google/flatbuffers/go"
)
type File struct {
	_tab flatbuffers.Table
}

func GetRootAsFile(buf []byte, offset flatbuffers.UOffsetT) *File {
	n := flatbuffers.GetUOffsetT(buf[offset:])
	x := &File{}
	x.Init(buf, n + offset)
	return x
}

func (rcv *File) Init(buf []byte, i flatbuffers.UOffsetT) {
	rcv._tab.Bytes = buf
	rcv._tab.Pos = i
}

func (rcv *File) Name() string {
	o := flatbuffers.UOffsetT(rcv._tab.Offset(4))
	if o != 0 {
		return rcv._tab.String(o + rcv._tab.Pos)
	}
	return ""
}

func (rcv *File) Size() uint64 {
	o := flatbuffers.UOffsetT(rcv._tab.Offset(6))
	if o != 0 {
		return rcv._tab.GetUint64(o + rcv._tab.Pos)
	}
	return 0
}

func FileStart(builder *flatbuffers.Builder) { builder.StartObject(2) }
func FileAddName(builder *flatbuffers.Builder, name flatbuffers.UOffsetT) { builder.PrependUOffsetTSlot(0, flatbuffers.UOffsetT(name), 0) }
func FileAddSize(builder *flatbuffers.Builder, size uint64) { builder.PrependUint64Slot(1, size, 0) }
func FileEnd(builder *flatbuffers.Builder) flatbuffers.UOffsetT { return builder.EndObject() }
