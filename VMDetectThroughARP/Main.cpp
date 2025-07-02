#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <iostream>
#include <vector>
#include <string>
#include <winsock2.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <iomanip>
#include <algorithm>
#include <unordered_map>
#include <unordered_set>
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")


std::vector<std::pair<std::string, std::string>> GetARPTable()
{
    PMIB_IPNETTABLE pArpTable = nullptr;
    ULONG tableSize = 0;
    std::vector<std::pair<std::string, std::string>> filteredDevices;

    if (GetIpNetTable(pArpTable, &tableSize, FALSE) == ERROR_INSUFFICIENT_BUFFER) 
    {
        pArpTable = (PMIB_IPNETTABLE)malloc(tableSize);
        if (!pArpTable) return filteredDevices;
    }

    if (GetIpNetTable(pArpTable, &tableSize, FALSE) != NO_ERROR)
    {
        free(pArpTable);
        return filteredDevices;
    }

    for (DWORD i = 0; i < pArpTable->dwNumEntries; i++)
    {
        auto& entry = pArpTable->table[i];

        char ipStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &entry.dwAddr, ipStr, INET_ADDRSTRLEN);


        char macStr[18];
        snprintf(macStr, sizeof(macStr), "%02X-%02X-%02X-%02X-%02X-%02X",
            entry.bPhysAddr[0], entry.bPhysAddr[1], entry.bPhysAddr[2],
            entry.bPhysAddr[3], entry.bPhysAddr[4], entry.bPhysAddr[5]);

        filteredDevices.emplace_back(ipStr, macStr);
    }

    free(pArpTable);
    return filteredDevices;
}
bool IsBroadcastMAC(const std::string& mac) 
{
    return mac == "FF-FF-FF-FF-FF-FF";
}
bool IsBroadcastIP(const std::string& ip) 
{
    return ip == "255.255.255.255" || ip.substr(ip.find_last_of('.') + 1) == "255";
}
bool IsMulticastIP(const std::string& ip)
{
    // Extract the first octet
    int firstOctet = std::stoi(ip.substr(0, ip.find('.')));
    return firstOctet >= 224 && firstOctet <= 239;
}
bool IsVMFromMac(const std::string& mac)
{
    std::string oui = mac.substr(0, 8);
    if (oui == "00-50-56" || oui == "00-0C-29" || oui == "00-05-69" || oui == "00-1C-14") return true;
    if (oui == "08-00-27") return true;
    if (oui == "00-03-FF") return true;
    if (oui == "00-1C-42") return true;
    if (oui == "52-54-00") return true;
    if (oui == "54-52-00") return true;
    if (oui == "00-16-3E") return true;
    if (oui == "00-21-F6") return true;
    if (oui == "00-0F-4B") return true;
    if (oui == "00-15-5D") return true;
    if (oui == "00-E0-4C") return true;
    if (oui == "00-1B-21") return true;
    if (oui == "00-14-4F") return true;
    if (oui == "00-50-F2") return true;
    if (oui == "00-17-F2") return true;
    if (oui == "AC-DE-48") return true;
    if (oui == "DE-AD-BE") return true;
    if (oui == "00-13-21") return true;
    if (oui == "00-24-E8") return true;
    if (oui == "00-26-BB") return true;
    if (oui == "00-1A-A0") return true;
    if (oui == "02-42-AC") return true;
    if (oui == "00-0F-EA") return true;
    if (oui == "00-18-8B") return true;
    if (oui == "00-22-4D") return true;
    if (oui == "00-0D-3A") return true;
    if (oui == "00-1B-17") return true;
    if (oui == "00-11-0A") return true;
    if (oui == "02-00-00") return true;
    if (oui == "06-00-00") return true;
    return false;
}
bool IsValidARPEntry(const std::pair<std::string, std::string>& entry)
{
    const std::string& ip = entry.first;
    const std::string& mac = entry.second;

    if (mac.length() != 17 || mac == "00-00-00-00-00-00") return false;
    if (IsBroadcastMAC(mac)) return false;
    if (IsMulticastIP(ip)) return false;
    if (IsBroadcastIP(ip)) return false;
    if (ip.rfind("169.254.", 0) == 0) return false;

  
    return true;
}
std::vector<std::pair<std::string, std::string>> FilterARPTable(
    const std::vector<std::pair<std::string, std::string>>& unfiltered
) 
{
    std::vector<std::pair<std::string, std::string>> filtered;
    std::unordered_set<std::string> seen; 

    for (const auto& entry : unfiltered) {
        if (!IsValidARPEntry(entry)) continue;
  

        std::string key = entry.first + "|" + entry.second;
        if (seen.count(key)) continue;  

        seen.insert(key);
        filtered.push_back(entry);
    }

    return filtered;
}
void PrintARP()
{
    auto rawDevices = GetARPTable();
    auto devices = FilterARPTable(rawDevices);

    if (devices.empty()) return;

    std::cout << std::left;
std::cout << "MAC Address\n";

    for (const auto& device : devices) 
    {
     
        std::cout << device.second;

        std::string oui = device.second.substr(0, 8);

        if (IsVMFromMac(device.second))
		{
			std::cout << " (VM)";
		

        }
        std::cout << std::endl;
    }
}

void main()
{
    PrintARP();
    std::cin.get();
}