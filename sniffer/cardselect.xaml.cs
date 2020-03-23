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
    /// cardselect.xaml 的交互逻辑
    /// </summary>
    public partial class cardselect : Window
    {
        
        public cardselect()
        {
            InitializeComponent();
            this.SizeChanged += new System.Windows.SizeChangedEventHandler(MainWindow_Resize);
        }
        public int Selectcard = -1;

        private void MainWindow_Resize(object sender, System.EventArgs e)
        {
            var lasth = this.Height - 90;
            var t = this.Sure.Margin;
            t.Top = lasth;
            t.Left = this.Width / 2 - 80;
            this.Sure.Margin = t;
        }
        private void Sure_Click(object sender, RoutedEventArgs e)
        {
            if(this.Cards.SelectedItem == null)
            {
                MessageBox.Show("please select a netword card");
                return;
            }
            Selectcard = this.Cards.Items.IndexOf(this.Cards.SelectedItem);
            this.Close();
        }
    }
}
