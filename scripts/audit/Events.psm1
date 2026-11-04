#Requires -Version 7.4
Set-StrictMode -Version Latest

function Initialize-NetworkEventObserver {
    if ('NetworkSkill.ChangeObserver' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Win32;
using Microsoft.Win32.SafeHandles;
namespace NetworkSkill {
    public sealed class ChangeEvent {
        public string Kind { get; set; }
        public int NotificationType { get; set; }
        public string At { get; set; }
        public long StopwatchTicks { get; set; }
    }
    public sealed class ChangeObserver : IDisposable {
        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate void IpCallback(IntPtr context, IntPtr row, int kind);
        [DllImport("iphlpapi.dll")]
        private static extern uint NotifyRouteChange2(ushort family, IpCallback callback, IntPtr context,
            [MarshalAs(UnmanagedType.U1)] bool initial, out IntPtr handle);
        [DllImport("iphlpapi.dll")]
        private static extern uint NotifyIpInterfaceChange(ushort family, IpCallback callback, IntPtr context,
            [MarshalAs(UnmanagedType.U1)] bool initial, out IntPtr handle);
        [DllImport("iphlpapi.dll")]
        private static extern uint NotifyUnicastIpAddressChange(ushort family, IpCallback callback, IntPtr context,
            [MarshalAs(UnmanagedType.U1)] bool initial, out IntPtr handle);
        [DllImport("iphlpapi.dll")]
        private static extern uint CancelMibChangeNotify2(IntPtr handle);
        [DllImport("advapi32.dll")]
        private static extern int RegNotifyChangeKeyValue(SafeRegistryHandle key,
            [MarshalAs(UnmanagedType.Bool)] bool subtree, uint filter, SafeWaitHandle signal,
            [MarshalAs(UnmanagedType.Bool)] bool asynchronous);
        private readonly ConcurrentQueue<ChangeEvent> events = new ConcurrentQueue<ChangeEvent>();
        private static readonly List<ChangeObserver> retained = new List<ChangeObserver>();
        private readonly IpCallback routeCallback, interfaceCallback, addressCallback;
        private readonly AutoResetEvent registrySignal = new AutoResetEvent(false);
        private RegistryKey registry;
        private Task registryTask;
        private IntPtr routeHandle, interfaceHandle, addressHandle;
        private int pending, dropped, stopped;
        public uint RouteStatus { get; private set; }
        public uint InterfaceStatus { get; private set; }
        public uint AddressStatus { get; private set; }
        public int ProxyStatus { get; private set; }
        public uint RouteCancelStatus { get; private set; }
        public uint InterfaceCancelStatus { get; private set; }
        public uint AddressCancelStatus { get; private set; }
        public int Dropped { get { return Volatile.Read(ref dropped); } }
        public ChangeObserver() {
            routeCallback = (context, row, kind) => Push("route", kind);
            interfaceCallback = (context, row, kind) => Push("interface", kind);
            addressCallback = (context, row, kind) => Push("address", kind);
            RouteStatus = NotifyRouteChange2(0, routeCallback, IntPtr.Zero, false, out routeHandle);
            InterfaceStatus = NotifyIpInterfaceChange(0, interfaceCallback, IntPtr.Zero, false, out interfaceHandle);
            AddressStatus = NotifyUnicastIpAddressChange(0, addressCallback, IntPtr.Zero, false, out addressHandle);
            ProxyStatus = -1;
            try {
                registry = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Internet Settings", false);
                if (registry != null) {
                    ProxyStatus = ArmProxy();
                    if (ProxyStatus == 0) registryTask = Task.Run(() => {
                        while (Volatile.Read(ref stopped) == 0) {
                            if (!registrySignal.WaitOne(100)) continue;
                            if (Volatile.Read(ref stopped) != 0) break;
                            Push("proxy-registry-key", 0);
                            ProxyStatus = ArmProxy();
                            if (ProxyStatus != 0) break;
                        }
                    });
                }
            } catch { ProxyStatus = -2; }
        }
        private int ArmProxy() {
            return RegNotifyChangeKeyValue(registry.Handle, false, 0x10000004,
                registrySignal.SafeWaitHandle, true);
        }
        private void Push(string kind, int notification) {
            if (Volatile.Read(ref stopped) != 0) return;
            if (Interlocked.Increment(ref pending) > 2048) {
                Interlocked.Decrement(ref pending);
                Interlocked.Increment(ref dropped);
                return;
            }
            events.Enqueue(new ChangeEvent { Kind = kind, NotificationType = notification,
                At = DateTimeOffset.UtcNow.ToString("o"), StopwatchTicks = Stopwatch.GetTimestamp() });
        }
        public ChangeEvent[] Drain() {
            var items = new List<ChangeEvent>();
            ChangeEvent item;
            while (events.TryDequeue(out item)) { Interlocked.Decrement(ref pending); items.Add(item); }
            return items.ToArray();
        }
        public void Dispose() {
            if (Interlocked.Exchange(ref stopped, 1) != 0) return;
            if (routeHandle != IntPtr.Zero) RouteCancelStatus = CancelMibChangeNotify2(routeHandle);
            if (interfaceHandle != IntPtr.Zero) InterfaceCancelStatus = CancelMibChangeNotify2(interfaceHandle);
            if (addressHandle != IntPtr.Zero) AddressCancelStatus = CancelMibChangeNotify2(addressHandle);
            registrySignal.Set();
            if (registryTask != null) registryTask.GetAwaiter().GetResult();
            if (registry != null) registry.Dispose();
            registrySignal.Dispose();
            if (RouteCancelStatus != 0 || InterfaceCancelStatus != 0 || AddressCancelStatus != 0) {
                lock (retained) retained.Add(this);
            }
            GC.KeepAlive(routeCallback);
            GC.KeepAlive(interfaceCallback);
            GC.KeepAlive(addressCallback);
        }
    }
}
'@
}

function Invoke-NetworkEventWatch {
    param([string]$StateRoot, [string]$SkillRoot, [ValidateRange(1,120)][int]$DurationSeconds=15)
    if (-not $IsWindows) { return @{status='BLOCKED';reason='Windows is required.';networkChanges=$false} }
    Initialize-NetworkEventObserver
    $run = New-NetworkRunDirectory -StateRoot $StateRoot -SkillRoot $SkillRoot
    $observer = [NetworkSkill.ChangeObserver]::new()
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $batch = 0
    $total = 0
    $disposed = $false
    try {
        while ($clock.Elapsed.TotalSeconds -lt $DurationSeconds) {
            $events = @($observer.Drain())
            if ($events.Count) {
                Write-NetworkJson -Path (Join-Path $run ('events-{0:D5}.json' -f $batch)) -Object $events
                $total += $events.Count
                $batch++
            }
            Start-Sleep -Milliseconds 100
        }
        $observer.Dispose()
        $disposed = $true
        $remaining = @($observer.Drain())
        if ($remaining.Count) {
            Write-NetworkJson -Path (Join-Path $run ('events-{0:D5}.json' -f $batch)) -Object $remaining
            $total += $remaining.Count
        }
        $coverage = @{
            route=$observer.RouteStatus;interface=$observer.InterfaceStatus;address=$observer.AddressStatus;proxy=$observer.ProxyStatus
        }
        $cleanup = @{route=$observer.RouteCancelStatus;interface=$observer.InterfaceCancelStatus;address=$observer.AddressCancelStatus}
        $result = @{
            status=if (@(@($coverage.Values) + @($cleanup.Values) | Where-Object {$_ -ne 0}).Count) {'PARTIAL'} else {'PASS'}
            runDirectory=$run;coverage=$coverage;cleanup=$cleanup;events=$total;dropped=$observer.Dropped;durationSeconds=$DurationSeconds
            meaning='Native change notifications; no writer identity, full changed values or proof of causality.'
            networkChanges=$false
        }
        Write-NetworkJson -Path (Join-Path $run 'event-summary.json') -Object $result
        $result
    } finally {
        if (-not $disposed) { $observer.Dispose() }
        $clock.Stop()
    }
}

Export-ModuleMember -Function Initialize-NetworkEventObserver,Invoke-NetworkEventWatch
