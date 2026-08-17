import pythoncom
import wmi

pythoncom.CoInitialize()

c = wmi.WMI()

print("TESTING WMI")

try:

    cs = c.Win32_ComputerSystem()[0]

    print("Manufacturer:", cs.Manufacturer)
    print("Model:", cs.Model)

except Exception as e:

    print("SYSTEM ERROR")
    print(e)

try:

    bios = c.Win32_BIOS()[0]

    print("Serial:", bios.SerialNumber)
    print("BIOS:", bios.SMBIOSBIOSVersion)

except Exception as e:

    print("BIOS ERROR")
    print(e)

try:

    board = c.Win32_BaseBoard()[0]

    print("Board:", board.Manufacturer, board.Product)

except Exception as e:

    print("BOARD ERROR")
    print(e)

try:

    for gpu in c.Win32_VideoController():

        print("GPU:", gpu.Name)

except Exception as e:

    print("GPU ERROR")
    print(e)