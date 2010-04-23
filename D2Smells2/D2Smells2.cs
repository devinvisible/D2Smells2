// D2Smells2 - A Diablo 2 packet sniffer
// Copyright (C) 2010  devINVISIBLE
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.


using PacketDotNet;
using SharpPcap;
using System;
using System.Collections.Generic;
using System.Windows.Forms;

namespace D2Smells2
{
    public partial class D2Smells2 : Form
    {
        // Address family for IPV4
        private const int AF_INET = 2;

        private LivePcapDevice device;
        private PacketSniffer sniffer;
        
        public D2Smells2()
        {
            InitializeComponent();

            this.Closing += new System.ComponentModel.CancelEventHandler(this.D2Smells2_Closing);

            sniffer = new PacketSniffer(Log);
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                sniffer.StopSniffing();
                if (sniffer != null)
                {
                    sniffer.Dispose();
                }

                if (components != null)
                {
                    components.Dispose();
                }
            }
            base.Dispose(disposing);
        }

        private void D2Smells2_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            sniffer.StopSniffing();
        }

        private void D2Smells2_Load(object sender, EventArgs e)
        {
            LogSharpPcapVersion();
            //LogDeviceList();
            PopulateInterfaceCombobox();
        }

        private void LogSharpPcapVersion()
        {
            Log(String.Format("SharpPcap Version: {0}{1}", SharpPcap.Version.VersionString, Environment.NewLine));
        }

        private void LogDeviceList()
        {
            LivePcapDeviceList deviceList = LivePcapDeviceList.Instance;

            if (deviceList.Count < 1)
            {
                Log("No devices were found on this machine");
            }
            else
            {
                Log(String.Format("The following devices are available on this machine:{0}", Environment.NewLine));

                foreach (LivePcapDevice device in deviceList)
                {
                    Log(device.Interface.FriendlyName);
                    Log(String.Format("{0}: {1}", device.Description, device.Interface.Name));
                    PcapAddress address = GetIPV4Sockddr(device);
                    Log(address.ToString());
                }
            }
        }

        // Return the first IPv4 address found for the device
        private PcapAddress GetIPV4Sockddr(LivePcapDevice device)
        {
            foreach (PcapAddress address in device.Addresses)
            {
                if (address.Addr.sa_family == AF_INET)
                {
                    return address;
                }
            }
            return null;
        }
        
        void PopulateInterfaceCombobox()
        {   
            LivePcapDeviceList deviceList = LivePcapDeviceList.Instance;

            if (deviceList.Count > 0)
            {
                foreach (LivePcapDevice device in deviceList)
                {
                    PcapAddress address = GetIPV4Sockddr(device);
                    cbInterface.Items.Add(String.Format("{0} -- {1}", device.Interface.FriendlyName, address.Addr.ipAddress));
                }
            }
        }

        private void cbInterface_SelectedIndexChanged(object sender, EventArgs e)
        {
            device = LivePcapDeviceList.Instance[cbInterface.SelectedIndex];
        }

        delegate void LogDelegate(string text);
        private void Log(String text)
        {
            if (rtbLog.InvokeRequired)
            {
                LogDelegate d = new LogDelegate(Log);
                Invoke(d, new object[] { text });
            }
            else
            {
                rtbLog.Text = String.Format("{0}{1}{2}", rtbLog.Text, Environment.NewLine, text);
                rtbLog.SelectionStart = rtbLog.Text.Length - 1;
                rtbLog.ScrollToCaret();
            }
        }

        private void btnToggleSniffing_Click(object sender, EventArgs e)
        {
            if (device == null)
            {
                MessageBox.Show("Please select an interface", "D2Smells2 Error");
            }
            else
            {
                if (btnToggleSniffing.Text == "Start Sniffing")
                {
                    btnToggleSniffing.Text = "Stop Sniffing";
                    cbInterface.Enabled = false;
                    sniffer.StartSniffing(device);
                }
                else
                {
                    sniffer.StopSniffing();
                    cbInterface.Enabled = true;
                    btnToggleSniffing.Text = "Start Sniffing";
                }
            }
        }
    }
}
