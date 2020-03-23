using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PacketDotNet;
using SharpPcap;
using System.IO;
using Microsoft.Scripting.Hosting;
using Microsoft.Scripting;

namespace sniffer
{
    //<GridViewColumn Header = "src IP" Width ="70"  DisplayMemberBinding="{Binding SourceAddress}"/>
    //<GridViewColumn Header = "des IP"  Width ="70" DisplayMemberBinding="{Binding DestinationAddress}"/>
    //<GridViewColumn Header = "protocal"  Width ="70" DisplayMemberBinding="{Binding ProtocalType}"/>
    //<GridViewColumn Header = "length" Width ="70"  DisplayMemberBinding="{Binding TotalPacketLength}"/>
    //<GridViewColumn Header = "info" Width="Auto" DisplayMemberBinding="{Binding PacketInfo}"/>
    public class Protocol
    {
        public Packet p;
        public string SourceAddress { get; set; }
        public string DestinationAddress { get; set; }
        public string ProtocalType { get; set; }
        public int TotalPacketLength { get; set; }
        public string PacketInfo { get; set; }
        public List<Protocol> TreeView { get; set; }

        public int sport = 0;
        public int dport = 0;

        public Protocol(Packet p)
        {
            this.p = p;
            //ScriptEngine engine = Python.CreateEngine();
            TreeView = new List<Protocol>();
            var packet = p.Extract<TcpPacket>();
            if (packet != null)
            {
                var ipPacket = packet.ParentPacket as IPPacket;
                this.SourceAddress = string.Format("{0}:{1}", ipPacket.SourceAddress, packet.SourcePort);
                this.DestinationAddress = string.Format("{0}:{1}", ipPacket.DestinationAddress, packet.DestinationPort);
                sport = packet.SourcePort;
                dport = packet.DestinationPort;
                ProtocalType = "TCP";
                TotalPacketLength = packet.TotalPacketLength;
                if(packet.DestinationPort == 80 | packet.SourcePort == 80)
                {
                    if(packet.TotalPacketLength == 20 | packet.TotalPacketLength == 32)
                    {
                        return;
                    }
                    try
                    {
                        var http = new HttpHeader(packet.PayloadData);
                        ProtocalType = "HTTP";
                    }
                    catch (Exception)
                    {
                        return;
                    }
                }

                return;
            }
            var packet2 = p.Extract<UdpPacket>();
            if (packet2 != null)
            {
                var ipPacket = packet2.ParentPacket as IPPacket;
                this.SourceAddress = string.Format("{0}:{1}", ipPacket.SourceAddress, packet2.SourcePort);
                this.DestinationAddress = string.Format("{0}:{1}", ipPacket.DestinationAddress, packet2.DestinationPort);
                sport = packet2.SourcePort;
                dport = packet2.DestinationPort;
                ProtocalType = "UDP";
                TotalPacketLength = packet2.TotalPacketLength;
                return;
            }
            var arppacket = p.Extract<ArpPacket>();
            if (arppacket != null)
            {
                this.SourceAddress = string.Format("{0}", arppacket.SenderProtocolAddress);
                this.DestinationAddress = string.Format("{0}", arppacket.TargetProtocolAddress);
                ProtocalType = "ARP";
                TotalPacketLength = arppacket.TotalPacketLength;
                return;
            }
            var icmppacket = p.Extract<IcmpV4Packet>();
            if (icmppacket != null)
            {
                var ipPacket = icmppacket.ParentPacket as IPPacket;
                this.SourceAddress = string.Format("{0}", ipPacket.SourceAddress);
                this.DestinationAddress = string.Format("{0}", ipPacket.DestinationAddress);

                ProtocalType = "ICMP";
                TotalPacketLength = icmppacket.TotalPacketLength;
                return;
            }
            var igmppacket = p.Extract<IgmpV2Packet>();
            if (igmppacket != null)
            {
                var ipPacket = igmppacket.ParentPacket as IPPacket;
                this.SourceAddress = string.Format("{0}", ipPacket.SourceAddress);
                this.DestinationAddress = string.Format("{0}", ipPacket.DestinationAddress);

                ProtocalType = "IGMP";
                TotalPacketLength = igmppacket.TotalPacketLength;
                return;
            }

        }
    }
}
