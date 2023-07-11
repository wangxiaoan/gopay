package util

import "os"

func WriteDebugFile(d1 []byte, filePath string) {
	f, _ := os.Create(filePath) //创建文件
	defer f.Close()
	f.Write(d1) //写入文件(字节数组)
	f.Sync()
}
