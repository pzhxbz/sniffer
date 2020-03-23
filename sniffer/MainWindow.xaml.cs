using PacketDotNet;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace sniffer
{
    /// <summary>
    /// MainWindow.xaml 的交互逻辑
    /// </summary>
    public partial class MainWindow : Window
    {
        private Capture cap;
        private List<Button> buttons = new List<Button>();
        private bool is_stop = false;
        private List<Packet> packets;
        private List<Protocol> allitems = new List<Protocol>();
        private FiltterInfo FiltterInfo = new FiltterInfo();
        private HttpHeader ht;

        public MainWindow()
        {
            InitializeComponent();
            this.SizeChanged += new System.Windows.SizeChangedEventHandler(MainWindow_Resize);
            this.StateChanged += new EventHandler(MainWindow_Resize);

            cap = new Capture();


            cap.UpdatePacketCallback(this.PacketRecv);

            //Protocol.LoadScript();


            packets = new List<Packet>();
            this.packgelistview.SizeChanged += packgelistview_SizeChanged;
            this.packgelistview.SelectionChanged += SelectPackge;

            buttons.Add(this.selectbutton);
            buttons.Add(this.startbutton);
            buttons.Add(this.stopbutton);
            buttons.Add(this.filtterbutton);
            buttons.Add(this.analysisbutton);
            buttons.Add(this.clearbutton);

            for (int i = 1; i < buttons.Count; i++)
            {
                var a = buttons[i];
                var t = a.Margin;
                t.Left = buttons[i-1].Margin.Left + buttons[i - 1].Width + 20;
                if(Double.IsNaN(t.Left))
                {
                    t.Left = i * 50;
                }
                a.Margin = t;
            }
        }
            

        private void packgelistview_SizeChanged(object sender, SizeChangedEventArgs e)
        {
            ListView listView = sender as ListView;
            GridView gView = listView.View as GridView;

            var workingWidth = listView.ActualWidth - SystemParameters.VerticalScrollBarWidth; // take into account vertical scrollbar
            var col1 = 0.25;
            var col2 = 0.25;
            var col3 = 0.25;
            var col4 = 0.25;

            gView.Columns[0].Width = workingWidth * col1;
            gView.Columns[1].Width = workingWidth * col2;
            gView.Columns[2].Width = workingWidth * col3;
            gView.Columns[3].Width = workingWidth * col4;
        }
        private void MainWindow_Resize(object sender, System.EventArgs e)
        {

            double moWidth = 0;
            double moHeight = 0;

            if (this.WindowState == WindowState.Maximized)
            {
                var handle = new WindowInteropHelper(this).Handle;
                var screen = System.Windows.Forms.Screen.FromHandle(handle);
                moWidth = screen.Bounds.Width;
                moHeight = screen.Bounds.Height;
            }
            else
            {
                moWidth = this.Width;
                moHeight = this.Height;
            }

            this.infoview.Width = moWidth;
            this.infotext.Width = moWidth;
            this.packgeview.Width = moWidth;
            this.headerview.Width = moWidth;
            this.packgelistview.Width = moWidth;


            this.packgeview.Height = moHeight * 0.6;

            var t = this.headerview.Margin;
            //t.Top = moHeight * 0.6 + 30;
            t.Top = this.packgeview.Height + this.packgeview.Margin.Top;
            this.headerview.Margin = t;
            this.headerview.Height = 70;

            t = this.infoview.Margin;
            t.Top = this.headerview.Height + this.headerview.Margin.Top; ;
            this.infoview.Margin = t;

            this.infoview.Height = moHeight * 0.15;
            this.infotext.Height = moHeight * 0.15;
        }

        private void selectbutton_Click(object sender, RoutedEventArgs e)
        {
            cardselect s = new cardselect();
            var list = cap.GetDevices();
            while(list == null)
            {
                MessageBox.Show("waiting...");
                Thread.Sleep(100);
                list = cap.GetDevices();
            }
            foreach (var i in list)
            {
                s.Cards.Items.Add(i);
               
            }
            s.Show();
            s.Closed += select_window_close;
        }

        private void select_window_close(object sender, System.EventArgs e)
        {
            cardselect s = (cardselect)sender;
            if (s.Selectcard == -1)
            {
                return;
            }
            var list = cap.GetDevices();
            cap.SetDevice(s.Selectcard);
        }

        private void stopbutton_Click(object sender, RoutedEventArgs e)
        {
            is_stop = true;
            this.startbutton.IsEnabled = true;
            this.stopbutton.IsEnabled = false;
            cap.Stop();
        }

        private  void  startbutton_Click(object sender, RoutedEventArgs e)
        {
            this.startbutton.IsEnabled = false;
            this.stopbutton.IsEnabled = true;
            cap.Start();
            is_stop = false;
        }

        public void PacketRecv(Packet p)
        {
            packets.Add(p);
            var ui = new Thread(() => {
                this.Dispatcher.Invoke(new Action(() =>
                {
                    var t = new Protocol(p);
                    allitems.Add(t);
                    if (t.TotalPacketLength != 0)
                    {
                        if (this.FiltterInfo.SPort != 0)
                        {
                            if(t.sport!=this.FiltterInfo.SPort)
                            {
                                return;
                            }
                        }
                        if (this.FiltterInfo.DPort != 0)
                        {
                            if (t.dport != this.FiltterInfo.DPort)
                            {
                                return;
                            }
                        }
                        switch(t.ProtocalType)
                        {
                            case "TCP": if (this.FiltterInfo.TCP == true) { packgelistview.Items.Add(t); }break;
                            case "HTTP": if (this.FiltterInfo.TCP == true) { packgelistview.Items.Add(t); } break;
                            case "UDP": if (this.FiltterInfo.UDP == true) { packgelistview.Items.Add(t); } break;
                            case "ARP": if (this.FiltterInfo.ARP == true) { packgelistview.Items.Add(t); } break;
                            case "ICMP": if (this.FiltterInfo.ICMP == true) { packgelistview.Items.Add(t); } break;
                            case "IGMP": if (this.FiltterInfo.IGMP == true) { packgelistview.Items.Add(t); } break;
                        }
                       
                    }
                }));
            });
            ui.Start();
            ui.Join();
            return;
        }
     

        private void filtterbutton_Click(object sender, RoutedEventArgs e)
        {
            Filtter f = new Filtter();
            f.Closed += this.filtter_window_close;
            f.Show();
        }

        private void filtter_window_close(object sender, System.EventArgs e)
        {
            Filtter s = (Filtter)sender;
            this.FiltterInfo = s.filtterInfo;
            var ui = new Thread(() => {
                this.Dispatcher.Invoke(new Action(() =>
                {
                    packgelistview.Items.Clear();
                    foreach (Protocol t in this.allitems)
                    {
                        if (this.FiltterInfo.SPort != 0)
                        {
                            if (t.sport != this.FiltterInfo.SPort)
                            {
                                continue;
                            }
                        }
                        if (this.FiltterInfo.DPort != 0)
                        {
                            if (t.dport != this.FiltterInfo.DPort)
                            {
                                continue;
                            }
                        }
                        switch (t.ProtocalType)
                        {
                            case "TCP": if (this.FiltterInfo.TCP == true) { packgelistview.Items.Add(t); } break;
                            case "HTTP": if (this.FiltterInfo.TCP == true) { packgelistview.Items.Add(t); } break;
                            case "UDP": if (this.FiltterInfo.UDP == true) { packgelistview.Items.Add(t); } break;
                            case "ARP": if (this.FiltterInfo.ARP == true) { packgelistview.Items.Add(t); } break;
                            case "ICMP": if (this.FiltterInfo.ICMP == true) { packgelistview.Items.Add(t); } break;
                            case "IGMP": if (this.FiltterInfo.IGMP == true) { packgelistview.Items.Add(t); } break;
                        }
                    }
                }));
            });
            ui.Start();
            //ui.Join();
        }

        private void packgeview_PreviewMouseWheel(object sender, MouseWheelEventArgs e)
        {
            {
                if (e.Delta > 0)
                {
                    packgeview.LineUp();
                }
                if (e.Delta < 0)
                {
                    packgeview.LineDown();
                }
            }
        }

        private void SelectPackge(object sender, SelectionChangedEventArgs args)
        {
            //ListBoxItem lbi = ((sender as ListBox).SelectedItem as ListBoxItem);
            //tb.Text = "   You selected " + lbi.Content.ToString() + ".";
            var lbi = ((sender as ListView).SelectedItem as Protocol);
            if(lbi == null)
            {
                return;
            }
            
            packinfo.Text = lbi.p.ToString().Replace(",",",\r\n");

            var data = lbi.p.PayloadPacket.Bytes;
            if(data == null)
            {
                return;
            }
            string text = "";

            for (int i=0;i<data.Length;i+=16)
            {
                byte[] t = new byte[16];
                if(data.Length - i < 16)
                {
                    Array.Copy(data, i, t, 0, data.Length - i);
                }
                else
                {
                    Array.Copy(data, i, t, 0, 16);
                }   
                text += _toHex(t) + "\r\n";
            }
            infotext.Text = text;

        }

        private string _toHex(byte[] b)
        {
            string hex =  BitConverter.ToString(b).Replace("-", "\t");
            string ori = "";
            foreach(var i in b)
            {
                if(i <= 0x20 || i > 0x7f)
                {
                    ori += '.';
                }
                else
                {
                    ori += (char)(i);
                }
            }
            return hex + '\t' + ori;
        }

        private void clearbutton_Click(object sender, RoutedEventArgs e)
        {
            this.allitems.Clear();
            this.packets.Clear();
            var ui = new Thread(() => {
                this.Dispatcher.Invoke(new Action(() =>
                {
                    packgelistview.Items.Clear();
                }));
            });
            ui.Start();
        }
        private void analysisbutton_Click(object sender, RoutedEventArgs e)
        {
            if(this.allitems.Count == 0)
            {
                MessageBox.Show("no data");
                return;
            }
            Analysis a = new Analysis();
            
            a.SetInfo(this.allitems);
            a.Show();
        }
      
    }
}
