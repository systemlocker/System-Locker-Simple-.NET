using System.ComponentModel;
using System.Diagnostics;
using System.Net.NetworkInformation;
using System.Runtime.Versioning;
using System.Security.Cryptography;
using System.Text;

namespace SystemLocker.Simple.Hwid;

/// <summary>
/// Hardware-derived device identifiers per the shared System Locker HWID
/// specification: factors are normalized, wrapped as
/// <c>factor=&lt;name&gt;|value=&lt;value&gt;</c>, joined in a fixed order, and
/// hashed with SHA-256 (base64url, unpadded).
/// </summary>
public static class HwidComposer
{
    private static readonly string[] FactorOrder =
    {
        "machine_guid", "product_uuid", "board_serial", "cpu_id", "disk_serial", "mac",
    };

    private static readonly HashSet<string> Placeholders = new(StringComparer.OrdinalIgnoreCase)
    {
        "", "none", "unknown", "default string", "to be filled by o.e.m.", "not specified", "system serial number",
    };

    /// <summary>Builds the canonical factor string; absent/placeholder factors contribute nothing.</summary>
    public static string CanonicalString(IReadOnlyDictionary<string, string> factors)
    {
        var parts = new List<string>();
        foreach (var name in FactorOrder)
        {
            if (!factors.TryGetValue(name, out var raw))
            {
                continue;
            }
            var value = Normalize(name, raw);
            if (value.Length == 0 || Placeholders.Contains(value))
            {
                continue;
            }
            parts.Add($"factor={name}|value={value}");
        }
        return string.Join("&", parts);
    }

    /// <summary>Hashes a canonical string into the final HWID.</summary>
    public static string FromCanonical(string canonical)
    {
        var digest = SHA256.HashData(Encoding.UTF8.GetBytes(canonical));
        return Convert.ToBase64String(digest).TrimEnd('=').Replace('+', '-').Replace('/', '_');
    }

    /// <summary>Derives an HWID from collected factors.</summary>
    public static string Compose(IReadOnlyDictionary<string, string> factors) =>
        FromCanonical(CanonicalString(factors));

    /// <summary>Trims, lowercases, strips NULs; MACs additionally drop separators.</summary>
    private static string Normalize(string name, string raw)
    {
        var value = raw.Replace("\0", "").Trim().ToLowerInvariant();
        if (name == "mac")
        {
            value = value.Replace(":", "").Replace("-", "").Replace(" ", "");
        }
        return value;
    }
}

/// <summary>Collects the available hardware factors on this machine.</summary>
public static class HwidCollector
{
    /// <summary>machine_guid fails closed; optional factors degrade gracefully.</summary>
    /// <exception cref="NotSupportedException">on platforms other than Windows and Linux.</exception>
    public static IReadOnlyDictionary<string, string> Collect()
    {
        if (OperatingSystem.IsWindows())
        {
            return WindowsCollector.Collect();
        }
        if (OperatingSystem.IsLinux())
        {
            return LinuxCollector.Collect();
        }
        throw new NotSupportedException(
            "hwid: hardware factor collection is not supported on this platform. Supply your own HWID through the configuration instead.");
    }

    /// <summary>Derives the HWID for this machine in one call.</summary>
    public static string DeviceHwid() => HwidComposer.Compose(Collect());
}

[SupportedOSPlatform("windows")]
file static class WindowsCollector
{
    public static IReadOnlyDictionary<string, string> Collect()
    {
        var machineGuid = RegistryValue(@"HKLM\SOFTWARE\Microsoft\Cryptography", "MachineGuid");
        if (machineGuid.Length == 0)
        {
            throw new InvalidOperationException("hwid: machine GUID unavailable");
        }

        var factors = new Dictionary<string, string> { ["machine_guid"] = machineGuid };

        var hardwareId = RegistryValue(
            @"HKLM\SYSTEM\CurrentControlSet\Control\SystemInformation", "ComputerHardwareId");
        if (hardwareId.Length > 0)
        {
            factors["product_uuid"] = hardwareId.Trim('{', '}');
        }

        var boardSerial = RegistryValue(
            @"HKLM\HARDWARE\DESCRIPTION\System\BIOS", "BaseBoardSerialNumber");
        if (boardSerial.Length > 0)
        {
            factors["board_serial"] = boardSerial;
        }

        var cpuId = RegistryValue(
            @"HKLM\HARDWARE\DESCRIPTION\System\CentralProcessor\0", "Identifier");
        if (cpuId.Length > 0)
        {
            factors["cpu_id"] = cpuId;
        }

        var mac = FirstPhysicalMac();
        if (mac is not null)
        {
            factors["mac"] = mac;
        }
        return factors;
    }

    /// <summary>Reads one string value through reg.exe, keeping the library dependency-free.</summary>
    private static string RegistryValue(string path, string name)
    {
        try
        {
            using var process = Process.Start(new ProcessStartInfo
            {
                FileName = "reg",
                Arguments = $"query \"{path}\" /v {name}",
                RedirectStandardOutput = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            });
            if (process is null)
            {
                return "";
            }
            var output = process.StandardOutput.ReadToEnd();
            process.WaitForExit(10_000);
            foreach (var line in output.Split('\n'))
            {
                var fields = line.Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
                for (var index = 1; index < fields.Length - 1; index++)
                {
                    if (string.Equals(fields[index], "REG_SZ", StringComparison.OrdinalIgnoreCase))
                    {
                        return string.Join(" ", fields[(index + 1)..]);
                    }
                }
            }
        }
        catch (Exception error) when (error is Win32Exception or InvalidOperationException)
        {
        }
        return "";
    }

    private static string? FirstPhysicalMac()
    {
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback ||
                nic.NetworkInterfaceType == NetworkInterfaceType.Tunnel)
            {
                continue;
            }
            var address = nic.GetPhysicalAddress().GetAddressBytes();
            if (address.Length != 6 || address.All(static b => b == 0))
            {
                continue;
            }
            var description = nic.Description.ToLowerInvariant();
            if (description.Contains("virtual") || description.Contains("vmware") ||
                description.Contains("hyper-v") || description.Contains("wsl") ||
                description.Contains("tailscale"))
            {
                continue;
            }
            return string.Join(":", address.Select(static b => b.ToString("x2")));
        }
        return null;
    }
}

file static class LinuxCollector
{
    public static IReadOnlyDictionary<string, string> Collect()
    {
        var machineId = ReadTrimmed("/etc/machine-id");
        if (machineId.Length == 0)
        {
            machineId = ReadTrimmed("/var/lib/dbus/machine-id");
        }
        if (machineId.Length == 0)
        {
            throw new InvalidOperationException("hwid: /etc/machine-id unavailable");
        }

        var factors = new Dictionary<string, string> { ["machine_guid"] = machineId };

        var productUuid = ReadTrimmed("/sys/class/dmi/id/product_uuid");
        if (productUuid.Length > 0)
        {
            factors["product_uuid"] = productUuid;
        }
        var boardSerial = ReadTrimmed("/sys/class/dmi/id/board_serial");
        if (boardSerial.Length > 0)
        {
            factors["board_serial"] = boardSerial;
        }
        var cpuSerial = CpuSerial();
        if (cpuSerial.Length > 0)
        {
            factors["cpu_id"] = cpuSerial;
        }
        var disk = DiskSerial();
        if (disk.Length > 0)
        {
            factors["disk_serial"] = disk;
        }
        var mac = FirstPhysicalMac();
        if (mac is not null)
        {
            factors["mac"] = mac;
        }
        return factors;
    }

    private static string ReadTrimmed(string path)
    {
        try
        {
            return File.ReadAllText(path).Trim();
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or FileNotFoundException)
        {
            return "";
        }
    }

    private static string CpuSerial()
    {
        try
        {
            foreach (var line in File.ReadLines("/proc/cpuinfo"))
            {
                var separator = line.IndexOf(':');
                if (separator > 0 && line[..separator].Trim() == "Serial")
                {
                    return line[(separator + 1)..].Trim();
                }
            }
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or FileNotFoundException)
        {
        }
        return "";
    }

    private static string DiskSerial()
    {
        try
        {
            foreach (var entry in Directory.EnumerateFileSystemEntries("/sys/block").OrderBy(static p => p, StringComparer.Ordinal))
            {
                var name = Path.GetFileName(entry);
                if (name.StartsWith("loop") || name.StartsWith("ram") || name.StartsWith("dm-"))
                {
                    continue;
                }
                foreach (var candidate in new[] { "device/ident", "device/serial", "serial" })
                {
                    var serial = ReadTrimmed(Path.Combine(entry, candidate));
                    if (serial.Length > 0)
                    {
                        return serial;
                    }
                }
            }
        }
        catch (Exception error) when (error is IOException or UnauthorizedAccessException or DirectoryNotFoundException)
        {
        }
        return "";
    }

    private static string? FirstPhysicalMac()
    {
        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback ||
                nic.NetworkInterfaceType == NetworkInterfaceType.Tunnel)
            {
                continue;
            }
            var name = nic.Name.ToLowerInvariant();
            if (name.StartsWith("veth") || name.StartsWith("docker") || name.StartsWith("br-") ||
                name.StartsWith("tun") || name.StartsWith("tap") || name.StartsWith("tailscale") ||
                name.StartsWith("zt") || name.StartsWith("wg") || name.StartsWith("virbr"))
            {
                continue;
            }
            var address = nic.GetPhysicalAddress().GetAddressBytes();
            if (address.Length != 6 || address.All(static b => b == 0))
            {
                continue;
            }
            return string.Join(":", address.Select(static b => b.ToString("x2")));
        }
        return null;
    }
}
