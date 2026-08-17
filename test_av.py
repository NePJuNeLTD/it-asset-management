import wmi

av = wmi.WMI(namespace="root\\SecurityCenter2")

for item in av.AntiVirusProduct():
    print(item.displayName)