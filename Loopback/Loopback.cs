using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Loopback
{
    /// <summary>
    /// https://docs.microsoft.com/en-us/archive/blogs/fiddler/revisiting-fiddler-and-win8-immersive-applications
    /// </summary>
    public class LoopUtil
    {
        //https://docs.microsoft.com/zh-cn/windows/win32/api/winnt/ns-winnt-sid_and_attributes
        [StructLayoutAttribute(LayoutKind.Sequential)]
        internal struct SID_AND_ATTRIBUTES
        {
            public IntPtr Sid;
            public uint Attributes;
        }

        [StructLayoutAttribute(LayoutKind.Sequential)]
        internal struct INET_FIREWALL_AC_CAPABILITIES
        {
            public uint count;
            public IntPtr capabilities; //SID_AND_ATTRIBUTES
        }

        [StructLayoutAttribute(LayoutKind.Sequential)]
        internal struct INET_FIREWALL_AC_BINARIES
        {
            public uint count;
            public IntPtr binaries;
        }

        [StructLayoutAttribute(LayoutKind.Sequential)]
        internal struct INET_FIREWALL_APP_CONTAINER
        {
            internal IntPtr appContainerSid;
            internal IntPtr userSid;

            [MarshalAs(UnmanagedType.LPWStr)]
            public string appContainerName;

            [MarshalAs(UnmanagedType.LPWStr)]
            public string displayName;

            [MarshalAs(UnmanagedType.LPWStr)]
            public string description;

            internal INET_FIREWALL_AC_CAPABILITIES capabilities;
            internal INET_FIREWALL_AC_BINARIES binaries;

            [MarshalAs(UnmanagedType.LPWStr)]
            public string workingDirectory;

            [MarshalAs(UnmanagedType.LPWStr)]
            public string packageFullName;
        }

        // Call this API to free the memory returned by the Enumeration API
        [DllImport("FirewallAPI.dll")]
        internal static extern void NetworkIsolationFreeAppContainers(IntPtr pACs);

        // Call this API to load the current list of LoopUtil-enabled AppContainers
        [DllImport("FirewallAPI.dll")]
        internal static extern uint NetworkIsolationGetAppContainerConfig(out uint pdwCntACs, out IntPtr appContainerSids);

        // Call this API to set the LoopUtil-exemption list
        [DllImport("FirewallAPI.dll")]
        private static extern uint NetworkIsolationSetAppContainerConfig(uint pdwCntACs, SID_AND_ATTRIBUTES[] appContainerSids);

        // Use this API to convert a string SID into an actual SID
        [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern bool ConvertStringSidToSid(string strSid, out IntPtr pSid);

        [DllImport("advapi32", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern bool ConvertSidToStringSid(
            [MarshalAs(UnmanagedType.LPArray)] byte[] pSID,
            out IntPtr ptrSid);

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool ConvertSidToStringSid(IntPtr pSid, out string strSid);

        // Use this API to convert a string reference (e.g. "@{blah.pri?ms-resource://whatever}") into a plain string
        [DllImport("shlwapi.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
        internal static extern int SHLoadIndirectString(string pszSource, StringBuilder pszOutBuf);

        // Call this API to enumerate all of the AppContainers on the system
        [DllImport("FirewallAPI.dll")]
        internal static extern uint NetworkIsolationEnumAppContainers(uint Flags, out uint pdwCntPublicACs, out IntPtr ppACs);

        //        DWORD NetworkIsolationEnumAppContainers(
        //  _In_   DWORD Flags,
        //  _Out_  DWORD *pdwNumPublicAppCs,
        //  _Out_  PINET_FIREWALL_APP_CONTAINER *ppPublicAppCs
        //);

        //https://docs.microsoft.com/zh-cn/windows/win32/api/netfw/ne-netfw-netiso_flag
        private enum NETISO_FLAG
        {
#pragma warning disable CA1712 // Do not prefix enum values with type name
            NETISO_FLAG_FORCE_COMPUTE_BINARIES = 0x1,
            NETISO_FLAG_MAX = 0x2
#pragma warning restore CA1712 // Do not prefix enum values with type name
        }

        public class AppContainer
        {
            public string appContainerName { get; set; }
            public string displayName { get; set; }
            public string workingDirectory { get; set; }
            public string StringSid { get; set; }
            public List<uint> capabilities { get; set; }
            public bool LoopUtil { get; set; }

            public AppContainer(string _appContainerName, string _displayName, string _workingDirectory, IntPtr _sid)
            {
                appContainerName = _appContainerName;
                displayName = _displayName;
                workingDirectory = _workingDirectory;
                ConvertSidToStringSid(_sid, out string tempSid);
                StringSid = tempSid;
            }
        }

        internal List<LoopUtil.INET_FIREWALL_APP_CONTAINER> _AppList;
        internal List<LoopUtil.SID_AND_ATTRIBUTES> _AppListConfig;
        public List<AppContainer> Apps = new List<AppContainer>();
        internal IntPtr _pACs;

        public LoopUtil()
        {
            LoadApps();
        }

        public void LoadApps()
        {
            Apps.Clear();
            _pACs = IntPtr.Zero;
            //Full List of Apps
            _AppList = PI_NetworkIsolationEnumAppContainers();
            //List of Apps that have LoopUtil enabled.
            _AppListConfig = PI_NetworkIsolationGetAppContainerConfig();
            foreach (var PI_app in _AppList)
            {
                AppContainer app = new AppContainer(PI_app.appContainerName, PI_app.displayName, PI_app.workingDirectory, PI_app.appContainerSid);

                var app_capabilities = LoopUtil.getCapabilites(PI_app.capabilities);
                if (app_capabilities.Count > 0)
                {
                    //var sid = new SecurityIdentifier(app_capabilities[0], 0);

                    IntPtr arrayValue = IntPtr.Zero;
                    //var b = LoopUtil.ConvertStringSidToSid(app_capabilities[0].Sid, out arrayValue);
                    //string mysid;
                    //var b = LoopUtil.ConvertSidToStringSid(app_capabilities[0].Sid, out mysid);
                }
                app.LoopUtil = CheckLoopback(PI_app.appContainerSid);
                Apps.Add(app);
            }
        }

        private bool CheckLoopback(IntPtr intPtr)
        {
            foreach (SID_AND_ATTRIBUTES item in _AppListConfig)
            {
                string right;
                ConvertSidToStringSid(item.Sid, out string left);
                ConvertSidToStringSid(intPtr, out right);

                if (left == right)
                {
                    return true;
                }
            }
            return false;
        }

        private static List<SID_AND_ATTRIBUTES> getCapabilites(INET_FIREWALL_AC_CAPABILITIES cap)
        {
            List<SID_AND_ATTRIBUTES> mycap = new List<SID_AND_ATTRIBUTES>();

            IntPtr arrayValue = cap.capabilities;

            var structSize = Marshal.SizeOf(typeof(SID_AND_ATTRIBUTES));
            for (var i = 0; i < cap.count; i++)
            {
                var cur = (SID_AND_ATTRIBUTES)Marshal.PtrToStructure(arrayValue, typeof(SID_AND_ATTRIBUTES));
                mycap.Add(cur);
                arrayValue = new IntPtr((long)(arrayValue) + (long)(structSize));
            }

            return mycap;
        }

        private static List<SID_AND_ATTRIBUTES> getContainerSID(INET_FIREWALL_AC_CAPABILITIES cap)
        {
            List<SID_AND_ATTRIBUTES> mycap = new List<SID_AND_ATTRIBUTES>();

            IntPtr arrayValue = cap.capabilities;

            var structSize = Marshal.SizeOf(typeof(SID_AND_ATTRIBUTES));
            for (var i = 0; i < cap.count; i++)
            {
                var cur = (SID_AND_ATTRIBUTES)Marshal.PtrToStructure(arrayValue, typeof(SID_AND_ATTRIBUTES));
                mycap.Add(cur);
                arrayValue = new IntPtr((long)(arrayValue) + (long)(structSize));
            }

            return mycap;
        }

        private static List<SID_AND_ATTRIBUTES> PI_NetworkIsolationGetAppContainerConfig()
        {
            IntPtr arrayValue = IntPtr.Zero;
            uint size = 0;
            var list = new List<SID_AND_ATTRIBUTES>();

            // Pin down variables
            GCHandle handle_pdwCntPublicACs = GCHandle.Alloc(size, GCHandleType.Pinned);
            GCHandle handle_ppACs = GCHandle.Alloc(arrayValue, GCHandleType.Pinned);

            uint retval = NetworkIsolationGetAppContainerConfig(out size, out arrayValue);

            var structSize = Marshal.SizeOf(typeof(SID_AND_ATTRIBUTES));
            for (var i = 0; i < size; i++)
            {
                var cur = (SID_AND_ATTRIBUTES)Marshal.PtrToStructure(arrayValue, typeof(SID_AND_ATTRIBUTES));
                list.Add(cur);
                arrayValue = new IntPtr((long)(arrayValue) + (long)(structSize));
            }

            //release pinned variables.
            handle_pdwCntPublicACs.Free();
            handle_ppACs.Free();

            return list;
        }

        private List<INET_FIREWALL_APP_CONTAINER> PI_NetworkIsolationEnumAppContainers()
        {
            IntPtr arrayValue = IntPtr.Zero;
            uint size = 0;
            var list = new List<INET_FIREWALL_APP_CONTAINER>();

            // Pin down variables
            GCHandle handle_pdwCntPublicACs = GCHandle.Alloc(size, GCHandleType.Pinned);
            GCHandle handle_ppACs = GCHandle.Alloc(arrayValue, GCHandleType.Pinned);

            //uint retval2 = NetworkIsolationGetAppContainerConfig( out size, out arrayValue);

            uint retval = NetworkIsolationEnumAppContainers((int)NETISO_FLAG.NETISO_FLAG_MAX, out size, out arrayValue);
            _pACs = arrayValue; //store the pointer so it can be freed when we close the form

            var structSize = Marshal.SizeOf(typeof(INET_FIREWALL_APP_CONTAINER));
            for (var i = 0; i < size; i++)
            {
                var cur = (INET_FIREWALL_APP_CONTAINER)Marshal.PtrToStructure(arrayValue, typeof(INET_FIREWALL_APP_CONTAINER));
                list.Add(cur);
                arrayValue = new IntPtr((long)(arrayValue) + (long)(structSize));
            }

            //release pinned variables.
            handle_pdwCntPublicACs.Free();
            handle_ppACs.Free();

            return list;
        }

        public bool SaveLoopbackState()
        {
            var countEnabled = CountEnabledLoopUtil();
            SID_AND_ATTRIBUTES[] arr = new SID_AND_ATTRIBUTES[countEnabled];
            int count = 0;

            for (int i = 0; i < Apps.Count; i++)
            {
                if (Apps[i].LoopUtil)
                {
                    arr[count].Attributes = 0;
                    //TO DO:
                    ConvertStringSidToSid(Apps[i].StringSid, out IntPtr ptr);
                    arr[count].Sid = ptr;
                    count++;
                }
            }

            if (NetworkIsolationSetAppContainerConfig((uint)countEnabled, arr) == 0)
            {
                return true;
            }
            else
            {
                return false;
            }
        }

        private int CountEnabledLoopUtil()
        {
            var count = 0;
            for (int i = 0; i < Apps.Count; i++)
            {
                if (Apps[i].LoopUtil)
                {
                    count++;
                }
            }
            return count;
        }

        public void FreeResources()
        {
            NetworkIsolationFreeAppContainers(_pACs);
        }
    }
}