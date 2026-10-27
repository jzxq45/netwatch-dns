//go:build windows

package main

import (
	"log/slog"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// Win32 constants (windows.h / shellapi.h / commctrl.h).
const (
	wmNull          = 0x0000
	wmDestroy       = 0x0002
	wmClose         = 0x0010
	wmCommand       = 0x0111
	wmNCDestroy     = 0x0082
	wmLButtonUp     = 0x0202
	wmLButtonDblClk = 0x0203
	wmRButtonUp     = 0x0205
	wmUser          = 0x0400
	wmTrayIcon      = wmUser + 100
	swHide          = 0
	swRestore       = 9
	nimAdd          = 0
	nimDelete       = 2
	nifMessage      = 0x00000001
	nifIcon         = 0x00000002
	nifTip          = 0x00000004
	mfString        = 0x00000000
	tpmRightButton  = 0x0002
	tpmBottomAlign  = 0x0020
	idiApplication  = 32512
	trayIconID      = 1
	trayMenuOpenID  = 1
	trayMenuExitID  = 2
	traySubclassID  = 1
	trayClass       = "NetwatchTrayWindow"
	trayTip         = "netwatch-dns - DNS monitor"
	trayOpenText    = "Открыть"
	trayExitText    = "Выход"
)

var (
	user32                   = syscall.NewLazyDLL("user32.dll")
	shell32                  = syscall.NewLazyDLL("shell32.dll")
	comctl32                 = syscall.NewLazyDLL("comctl32.dll")
	procRegisterClassExW     = user32.NewProc("RegisterClassExW")
	procCreateWindowExW      = user32.NewProc("CreateWindowExW")
	procDefWindowProcW       = user32.NewProc("DefWindowProcW")
	procGetMessageW          = user32.NewProc("GetMessageW")
	procTranslateMessage     = user32.NewProc("TranslateMessage")
	procDispatchMessageW     = user32.NewProc("DispatchMessageW")
	procPostMessageW         = user32.NewProc("PostMessageW")
	procPostQuitMessage      = user32.NewProc("PostQuitMessage")
	procDestroyWindowW       = user32.NewProc("DestroyWindow")
	procShowWindow           = user32.NewProc("ShowWindow")
	procSetForegroundWindow  = user32.NewProc("SetForegroundWindow")
	procLoadIconW            = user32.NewProc("LoadIconW")
	procGetModuleHandleW     = user32.NewProc("GetModuleHandleW")
	procCreatePopupMenu      = user32.NewProc("CreatePopupMenu")
	procAppendMenuW          = user32.NewProc("AppendMenuW")
	procTrackPopupMenuEx     = user32.NewProc("TrackPopupMenuEx")
	procDestroyMenu          = user32.NewProc("DestroyMenu")
	procGetCursorPos         = user32.NewProc("GetCursorPos")
	procSetWindowSubclass    = comctl32.NewProc("SetWindowSubclass")
	procRemoveWindowSubclass = comctl32.NewProc("RemoveWindowSubclass")
	procDefSubclassProc      = comctl32.NewProc("DefSubclassProc")
	procShellNotifyIconW     = shell32.NewProc("Shell_NotifyIconW")

	trayWndProc      = syscall.NewCallback(trayWindowProc)
	traySubclassProc uintptr
)

func init() {
	traySubclassProc = syscall.NewCallback(closeToTrayProc)
}

type point struct {
	X int32
	Y int32
}

type msg struct {
	HWnd     uintptr
	Message  uint32
	WParam   uintptr
	LParam   uintptr
	Time     uint32
	Pt       point
	LPrivate uint32
}

type wndClassEx struct {
	CbSize        uint32
	Style         uint32
	LpfnWndProc   uintptr
	CbClsExtra    int32
	CbWndExtra    int32
	HInstance     uintptr
	HIcon         uintptr
	HCursor       uintptr
	HbrBackground uintptr
	LpszMenuName  *uint16
	LpszClassName *uint16
	HIconSm       uintptr
}

type guid struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}

// notifyIconData mirrors NOTIFYICONDATAW (Vista+ layout).
type notifyIconData struct {
	CbSize           uint32
	HWnd             uintptr
	UID              uint32
	UFlags           uint32
	UCallbackMessage uint32
	HIcon            uintptr
	SzTip            [128]uint16
	DwState          uint32
	DwStateMask      uint32
	SzInfo           [256]uint16
	UTimeoutVersion  uint32
	SzInfoTitle      [64]uint16
	DwInfoFlags      uint32
	GuidItem         guid
	HBalloonIcon     uintptr
}

type trayState struct {
	mu       sync.Mutex
	hwndMain uintptr
	onExit   func()
	nid      notifyIconData
	added    bool
}

var tray trayState

// setupTray creates a hidden message window, adds the notification icon and
// starts its message loop on a dedicated OS thread. The returned cleanup
// removes the icon and stops the loop.
func setupTray(hwndMain uintptr, onExit func()) (cleanup func()) {
	ready := make(chan struct{})
	done := make(chan struct{})
	var hwndMsg uintptr

	tray.mu.Lock()
	tray.hwndMain = hwndMain
	tray.onExit = onExit
	tray.mu.Unlock()

	go func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		hwndMsg = createMessageWindow()
		if hwndMsg == 0 {
			slog.Warn("tray: message window creation failed")
			close(ready)
			return
		}
		if !addTrayIcon(hwndMsg) {
			slog.Warn("tray: Shell_NotifyIcon add failed")
		}
		close(ready)
		runTrayMessageLoop()
		close(done)
	}()

	<-ready
	if hwndMsg == 0 {
		return func() {}
	}
	return func() {
		removeTrayIcon()
		_, _, _ = procPostMessageW.Call(hwndMsg, wmClose, 0, 0)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
		}
	}
}

func createMessageWindow() uintptr {
	className, err := syscall.UTF16PtrFromString(trayClass)
	if err != nil {
		return 0
	}
	windowName, err := syscall.UTF16PtrFromString(trayTip)
	if err != nil {
		return 0
	}
	hInstance, _, _ := procGetModuleHandleW.Call(0)

	wc := wndClassEx{
		CbSize:        uint32(unsafe.Sizeof(wndClassEx{})),
		LpfnWndProc:   trayWndProc,
		HInstance:     hInstance,
		LpszClassName: className,
	}
	if ret, _, _ := procRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc))); ret == 0 {
		return 0
	}
	hwnd, _, _ := procCreateWindowExW.Call(
		0,
		uintptr(unsafe.Pointer(className)),
		uintptr(unsafe.Pointer(windowName)),
		0, 0, 0, 0, 0,
		0, 0, hInstance, 0,
	)
	return hwnd
}

func addTrayIcon(hwnd uintptr) bool {
	var nid notifyIconData
	nid.CbSize = uint32(unsafe.Sizeof(nid))
	nid.HWnd = hwnd
	nid.UID = trayIconID
	nid.UFlags = nifMessage | nifIcon | nifTip
	nid.UCallbackMessage = wmTrayIcon
	nid.HIcon, _, _ = procLoadIconW.Call(0, idiApplication)
	tip, _ := syscall.UTF16FromString(trayTip)
	copy(nid.SzTip[:], tip)

	ret, _, _ := procShellNotifyIconW.Call(nimAdd, uintptr(unsafe.Pointer(&nid)))
	if ret == 0 {
		return false
	}
	tray.mu.Lock()
	tray.nid = nid
	tray.added = true
	tray.mu.Unlock()
	return true
}

func removeTrayIcon() {
	tray.mu.Lock()
	defer tray.mu.Unlock()
	if !tray.added {
		return
	}
	_, _, _ = procShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&tray.nid)))
	tray.added = false
}

func runTrayMessageLoop() {
	var m msg
	for {
		ret, _, _ := procGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(ret) <= 0 {
			return
		}
		_, _, _ = procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		_, _, _ = procDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}
}

func trayWindowProc(hwnd, message, wparam, lparam uintptr) uintptr {
	switch uint32(message) {
	case wmTrayIcon:
		switch uint32(lparam & 0xFFFF) {
		case wmLButtonUp, wmLButtonDblClk:
			restoreMainWindow()
		case wmRButtonUp:
			showTrayMenu(hwnd)
		}
		return 0
	case wmCommand:
		switch uint32(wparam & 0xFFFF) {
		case trayMenuOpenID:
			restoreMainWindow()
		case trayMenuExitID:
			removeTrayIcon()
			tray.mu.Lock()
			onExit := tray.onExit
			tray.mu.Unlock()
			if onExit != nil {
				onExit()
			}
		}
		return 0
	case wmClose:
		_, _, _ = procDestroyWindowW.Call(hwnd)
		return 0
	case wmDestroy:
		_, _, _ = procPostQuitMessage.Call(0)
		return 0
	default:
		ret, _, _ := procDefWindowProcW.Call(hwnd, message, wparam, lparam)
		return ret
	}
}

func restoreMainWindow() {
	tray.mu.Lock()
	hwnd := tray.hwndMain
	tray.mu.Unlock()
	if hwnd == 0 {
		return
	}
	_, _, _ = procShowWindow.Call(hwnd, swRestore)
	_, _, _ = procSetForegroundWindow.Call(hwnd)
}

func showTrayMenu(hwnd uintptr) {
	menu, _, _ := procCreatePopupMenu.Call()
	if menu == 0 {
		return
	}
	defer func() { _, _, _ = procDestroyMenu.Call(menu) }()

	openText, _ := syscall.UTF16PtrFromString(trayOpenText)
	exitText, _ := syscall.UTF16PtrFromString(trayExitText)
	_, _, _ = procAppendMenuW.Call(menu, mfString, trayMenuOpenID, uintptr(unsafe.Pointer(openText)))
	_, _, _ = procAppendMenuW.Call(menu, mfString, trayMenuExitID, uintptr(unsafe.Pointer(exitText)))

	var pt point
	_, _, _ = procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))

	// Required so the popup closes when clicking elsewhere.
	_, _, _ = procSetForegroundWindow.Call(hwnd)
	_, _, _ = procTrackPopupMenuEx.Call(menu, tpmRightButton|tpmBottomAlign, uintptr(pt.X), uintptr(pt.Y), hwnd, 0)
	_, _, _ = procPostMessageW.Call(hwnd, wmNull, 0, 0)
}

// interceptCloseToTray hides the main window on WM_CLOSE instead of letting
// the webview destroy it.
func interceptCloseToTray(hwndMain uintptr) {
	if hwndMain == 0 {
		return
	}
	if ret, _, _ := procSetWindowSubclass.Call(hwndMain, traySubclassProc, traySubclassID, 0); ret == 0 {
		slog.Warn("tray: SetWindowSubclass failed")
	}
}

func closeToTrayProc(hwnd, message, wparam, lparam, id, refData uintptr) uintptr {
	if uint32(message) == wmClose {
		_, _, _ = procShowWindow.Call(hwnd, swHide)
		return 0
	}
	if uint32(message) == wmNCDestroy {
		_, _, _ = procRemoveWindowSubclass.Call(hwnd, traySubclassProc, id)
	}
	ret, _, _ := procDefSubclassProc.Call(hwnd, message, wparam, lparam)
	return ret
}
