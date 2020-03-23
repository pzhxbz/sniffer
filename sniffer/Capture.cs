using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Threading;

using SharpPcap;
using PacketDotNet;

namespace sniffer
{
    class Capture
    {
        private ICaptureDevice device;
        private CaptureDeviceList devices;
        private Thread t;
        private List<Packet> packets;
        private bool is_start = false;
        public delegate void UpdatePacket(Packet p);
        public UpdatePacket update = null;
        public Capture()
        {
            packets = new List<Packet>();
            t = new Thread(_getdevice);
            t.Start();

        }
        private void _getdevice()
        {
            devices = CaptureDeviceList.Instance;
        }
        public void Start()
        {
            if(is_start)
            {
                return;
            }
            is_start = true;
            int readTimeoutMilliseconds = 1000;
            device.Open(DeviceMode.Promiscuous, readTimeoutMilliseconds);
            new Thread(() => {
                try
                {
                    device.Capture();

                }
                catch(Exception)
                {
                    this.Stop();
                }
            }).Start();
        }
        public CaptureDeviceList GetDevices()
        {
            if(t.IsAlive)
            {
                return null;
            }
            //devices = CaptureDeviceList.Instance;
            return devices;
        }

        public void SetDevice(int id)
        {
            device = devices[id];
            device.OnPacketArrival +=
                new PacketArrivalEventHandler(this.device_OnPacketArrival);
        }
        private void device_OnPacketArrival(object sender, CaptureEventArgs e)
        {
            var time = e.Packet.Timeval.Date;
            var len = e.Packet.Data.Length;
            var packet = PacketDotNet.Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);
            
            if(update!=null)
            {
                update(packet);
            }
            else
            {
                packets.Add(packet);
            }
        }

        public List<Packet> GetPackets()
        {
            var res = packets;
            packets.Clear();
            return res;
        }

        public void Stop()
        {
            is_start = false;
            device.Close();
        }
        public void UpdatePacketCallback(UpdatePacket update)
        {
            this.update = update;
        }
    }
}
