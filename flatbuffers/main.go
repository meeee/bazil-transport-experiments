package main

import (
	"fmt"

	flatbuffers "github.com/google/flatbuffers/go"

	fb "./flatbuffers"
)

func main() {
	builder := flatbuffers.NewBuilder(0)
	fb.FileStart(builder)
	fb.FileAddName(builder, builder.CreateString("main.go"))
	fb.FileAddSize(builder, 123)
	mloc := fb.FileEnd(builder)
	builder.Finish(mloc)
	head := builder.Head()
	var bytes []byte = builder.Bytes[head : head+builder.Offset()]
	fmt.Printf("%T: %v (%d bytes)\n", bytes, bytes, len(bytes))
	// fmt.Printf("%s", bytes)

	file := fb.GetRootAsFile(bytes, 0)
	fmt.Printf("Name: %v Size: %v\n", file.Name(), file.Size())
	// str := builder.Crea
	// fb.File
	// fmt.Println(":)")
}
