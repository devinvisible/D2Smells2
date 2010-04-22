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
        
        public D2Smells2()
        {
            InitializeComponent();
        }

        private void D2Smells2_Load(object sender, EventArgs e)
        {
            LogSharpPcapVersion();
            LogDeviceList();
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
                    StartSniffing();
                }
                else
                {
                    StopSniffing();
                    cbInterface.Enabled = true;
                    btnToggleSniffing.Text = "Start Sniffing";
                }
            }
        }

        private void StartSniffing()
        {
            try
            {
                device.OnPacketArrival += new PacketArrivalEventHandler(device_OnPacketArrival);

                // Open the device for capturing
                int readTimeoutMilliseconds = 1000;
                //device.StopCaptureTimeout = new TimeSpan(0, 1, 0);
                device.Open(DeviceMode.Promiscuous, readTimeoutMilliseconds);

                device.StartCapture();
                Log("Sniffing started");
            }
            catch (Exception e)
            {
                Log(e.ToString());
            }
        }

        private void StopSniffing()
        {
            // threw PcapException
            try
            {
                device.StopCapture();
            }
            catch (PcapException)
            {
                // I'm not sure why the captureThread (PcapDeviceCaptureLoop.cs:197) won't join the calling
                // thread in a timely fashion.  Because of this, I'm eating this exception for now...
            }

            Log("Sniffing stopped");
        }

        private void device_OnPacketArrival(object sender, CaptureEventArgs e)
        {
            try
            {
                Packet p = Packet.ParsePacket(e.Packet);
                // We're given an EthernetPacket but I don't particularly care about that layer, so skip it
                p = p.PayloadPacket;
                Log(p.ToString());
            }
            catch (System.Threading.ThreadAbortException tae)
            {
                // device.StopCapture() will abort the capture thread
                // This will causes a ThreadAbortException if we're on the same thread
            }
            catch (Exception ex)
            {
                Log(ex.ToString());
            }
        }
    }
}
