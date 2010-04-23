using System;
using SharpPcap;
using PacketDotNet;
using System.Collections;
using System.Threading;

namespace D2Smells2
{
    class PacketSniffer : IDisposable
    {
        private LivePcapDevice device;

        private bool aborting;
        private bool disposed;

        private Queue packetQueue;
        private object packetLock;
        private Thread sniffingThread;
        private Thread decodingThread;
        private AutoResetEvent packetAvailiable;

        public delegate void LogDelegate(string text);
        LogDelegate Log;

        public PacketSniffer(LogDelegate logDelegate)
        {
            Log = logDelegate;

            aborting = false;
            device = null;
            packetLock = new object();
            packetAvailiable = new AutoResetEvent(false);
            disposed = false;
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!disposed)
            {
                if (disposing)
                {
                    StopSniffing();
                }
                disposed = true;
            }
        }

        // Filtering expression syntax: http://www.winpcap.org/docs/docs_40_2/html/group__language.html
        private String GetFilterExpression()
        {
            // ip[2:2] is the Total Length of the ip header and payload.

            // (ip[0] & 0x0f) is the low word of the first byte in the ip header
            // This is the IP Header Length (in dwords).  Multiply this by 4 to get the size in bytes.

            // (tcp[12] & 0xf0) is the high word of the 12th byte in the tcp header.  Divide by 0x10 to obtain the word.
            // This is the TCP Header Length (in dwords).  Multiply this by 4 to get the size in bytes.

            // We only want to see packets with a payload (Total Length - IP Header Length - TCP Header Length)

            return "(port 6112 or port 4000) and ((ip[2:2] - ((ip[0] & 0x0f) * 4) - (((tcp[12] & 0xf0) / 0x10) * 4) > 0))";
            //return "(port 6112 or port 4000) and (len >= 66)";
            //return "(port 6112 or port 4000)";
        }

        public bool StartSniffing(LivePcapDevice deviceToSniff)
        {
            try
            {
                device = deviceToSniff;

                // Open the device for capturing
                int readTimeoutMilliseconds = 1000;
                //device.StopCaptureTimeout = new TimeSpan(0, 1, 0);
                device.Open(DeviceMode.Promiscuous, readTimeoutMilliseconds);
                device.SetFilter(GetFilterExpression());

                packetQueue = new Queue();

                sniffingThread = new Thread(new ThreadStart(SnifferLoop));
                sniffingThread.Name = "Sniffing Thread";
                sniffingThread.IsBackground = true;
                sniffingThread.Start();

                decodingThread = new Thread(new ThreadStart(DecoderLoop));
                decodingThread.Name = "Decoding Thread";
                decodingThread.IsBackground = true;
                decodingThread.Start();

                Log("Sniffing started");
            }
            catch (Exception e)
            {
                Log(e.ToString());
                return false;
            }

            return true;
        }

        public bool StopSniffing()
        {
            try
            {
                aborting = true;

                if (sniffingThread != null)
                {
                    sniffingThread.Join();
                }

                if (device != null && device.Opened)
                {
                    device.Close();
                }

                if (decodingThread != null)
                {
                    decodingThread.Join();
                }

                aborting = false;
            }
            catch (Exception e)
            {
                Log(e.ToString());
                return false;
            }

            Log("Sniffing stopped");
            return true;
        }

        private void SnifferLoop()
        {
            RawPacket rawPacket = null;

            try
            {
                while (true)
                {
                    if (aborting)
                    {
                        // Signal the DecoderLoop to iterate one last time
                        packetAvailiable.Set();
                        return;
                    }

                    rawPacket = device.GetNextPacket();
                    if (rawPacket == null)
                    {
                        //    // Need to empty the buffer before updating filter because buffer gets reset when changing filter !
                        //    // This must happen as fast as possible to minimise risks of losing packets.
                        //    if (this.filterChanged)
                        //    {
                        //        lock (this.filterLock)
                        //        {
                        //            this.device.PcapSetFilter();
                        //            this.filterChanged = false;
                        //        }
                        //        this.DebugLog("filter updated");
                        //    }
                        continue;
                    }

                    lock (packetLock)
                    {
                        packetQueue.Enqueue(rawPacket);
                    }
                    packetAvailiable.Set();
                }
            }
            catch (Exception e)
            {
                Log(e.ToString());
            }
		}

        private void DecoderLoop()
        {
            RawPacket rawPacket = null;

            try
            {
                while (true)
                {
                    // Parse all the packets in queue
                    while (true)
                    {
                        if (aborting)
                        {
                            return;
                        }

                        lock (packetLock)
                        {
                            if (packetQueue.Count == 0)
                            {
                                break;
                            }

                            rawPacket = (RawPacket)packetQueue.Dequeue();
                            ParsePacket((IPv4Packet)Packet.ParsePacket(rawPacket).PayloadPacket);
                        }
				    }

                    if (this.aborting == true)
                    {
                        return;
                    }
				    // Wait for sniffer to signal at least one packet is availiable
				    this.packetAvailiable.WaitOne();
                }
            }
            catch (Exception e)
            {
                Log(e.ToString());
            }
        }

        void ParsePacket(IPv4Packet ipPacket)
        {
            TcpPacket tcpPacket = (TcpPacket)ipPacket.PayloadPacket;

            System.Text.StringBuilder sb = new System.Text.StringBuilder();

            sb.Append(String.Format("{0}:{1}", ipPacket.SourceAddress, tcpPacket.SourcePort));
            sb.Append(" --> ");
            sb.Append(String.Format("{0}:{1}", ipPacket.DestinationAddress, tcpPacket.DestinationPort));
            sb.AppendLine(String.Format(" Len = {0}", tcpPacket.PayloadData.Length));
            //sb.Append(" Data = ");

            //foreach (byte b in tcpPacket.PayloadData)
            //{
            //    sb.Append(String.Format("{0} ", b.ToString()));
            //}

            //sb.AppendLine(ByteArrayToHex(tcpPacket.PayloadData));
            sb.Append(FormatPacketData(tcpPacket.PayloadData));

            Log(sb.ToString());
        }

        /* Output Goal:
        0000  00 1c f0 6a ca f0 00 04  4b 18 23 21 08 00 45 00   ...j.... K.#!..E.
        0010  00 34 06 ed 40 00 80 06  00 00 c0 a8 00 c6 3f f0   .4..@... ......?.
        0020  ca 7f d2 88 17 e0 1f d6  c8 40 00 00 00 00 80 02   ........ .@......
        0030  20 00 cc 04 00 00 02 04  05 b4 01 03 03 02 01 01    ....... ........
        0040  04 02                                              ..               
        */
        private string FormatPacketData(byte[] barray)
        {
            byte b;
            char[] ascii = new char[16];
            System.Text.StringBuilder sb = new System.Text.StringBuilder();

            int rows = barray.Length / 16;
            if (barray.Length % 16 != 0) rows++;

            for (int i = 0; i < rows; i++)
            {
                sb.Append((i * 10).ToString().PadLeft(4, '0'));
                sb.Append("  ");

                // First eight bytes
                for (int j = 0; j < 8; j++)
                {
                    if ((i * 16) + j < barray.Length)
                    {
                        ascii[j] = (char)(barray[(i * 16) + j]);
                        b = ((byte)(barray[(i * 16) + j] >> 4));
                        sb.Append((char)(b > 9 ? b + 0x37 : b + 0x30));
                        b = ((byte)(barray[(i * 16) + j] & 0xF));
                        sb.Append((char)(b > 9 ? b + 0x37 : b + 0x30));
                        sb.Append(" ");
                    }
                    else
                    {
                        ascii[j] = ' ';
                        sb.Append("   ");
                    }
                }

                sb.Append(" ");

                // Next eight bytes
                for (int j = 8; j < 16; j++)
                {
                    if ((i * 16) + j < barray.Length)
                    {
                        ascii[j] = (char)(barray[(i * 16) + j]);
                        b = ((byte)(barray[(i * 16) + j] >> 4));
                        sb.Append((char)(b > 9 ? b + 0x37 : b + 0x30));
                        b = ((byte)(barray[(i * 16) + j] & 0xF));
                        sb.Append((char)(b > 9 ? b + 0x37 : b + 0x30));
                        sb.Append(" ");
                    }
                    else
                    {
                        ascii[j] = ' ';
                        sb.Append("   ");
                    }
                }
                
                sb.Append("  ");

                // Output the ascii
                for (int j = 0; j < 16; j++)
                {
                    // Only render certain characters
                    if ((byte)ascii[j] < 32 || (byte)ascii[j] >= 128)
                    {
                        sb.Append(".");
                    }
                    else
                    {
                        sb.Append(ascii[j]);
                    }
                }

                sb.Append(Environment.NewLine);
            }

            return sb.ToString();
        }
    }
}
