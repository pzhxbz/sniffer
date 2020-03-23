using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;

namespace sniffer
{
    /// <summary>
    /// Filtter.xaml 的交互逻辑
    /// </summary>
    /// 

    public class FiltterInfo 
    {
        public bool TCP = true;
        public bool UDP = true;
        public bool ARP = true;
        public bool ICMP = true;
        public bool IGMP = true;

        public int SPort = 0;
        public int DPort = 0;

        public FiltterInfo()
        {

        }

    }
        
    public partial class Filtter : Window
    {
        public FiltterInfo filtterInfo = new FiltterInfo();
        public Filtter()
        {
            InitializeComponent();
        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            filtterInfo.TCP = this.tcpcheck.IsChecked == true ? true : false;
            filtterInfo.UDP = this.udpcheck.IsChecked == true ? true : false;
            filtterInfo.ICMP = this.icmpcheck.IsChecked == true ? true : false;
            filtterInfo.IGMP = this.icmpcheck.IsChecked == true ? true : false;
            filtterInfo.ARP = this.arpcheck.IsChecked == true? true : false;
            if(this.sportcheck.IsChecked == true)
            {
                filtterInfo.SPort = int.Parse(this.sporttext.Text);
            }
            if (this.dportcheck.IsChecked == true)
            {
                filtterInfo.DPort = int.Parse(this.dporttext.Text);
            }
            this.Close();
        }
    }
}
