using System;
using System.Collections.Generic;
using System.Linq;
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
using System.Windows.Shapes;
using LiveCharts;
using LiveCharts.Wpf;

namespace sniffer
{
    /// <summary>
    /// Analysis.xaml 的交互逻辑
    /// </summary>
    /// 
    
    public partial class Analysis : Window
    {

        private List<Protocol> allitems;
        private bool is_http = true;
        public Analysis()
        {
            InitializeComponent();
            this.SizeChanged += MainWindow_Resize;
            this.StateChanged += new EventHandler(MainWindow_Resize);
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
            var t = this.updatebt.Margin;
            t.Left = moWidth - 65;
            t.Top = moHeight - 90;
            this.updatebt.Margin = t;
         
        }
        public void SetInfo(List<Protocol> allitems)
        {
            //graph
            this.allitems = allitems;
        }
        private void _http()
        {
            Dictionary<string, int> httpAnlysis = new Dictionary<string, int>();
            foreach (var i in allitems)
            {
                if (i.ProtocalType == "HTTP")
                {
                    if (i.dport == 80)
                    {
                        if (!httpAnlysis.ContainsKey(i.DestinationAddress))
                        {
                            httpAnlysis.Add(i.DestinationAddress, 1);
                        }
                        else
                        {
                            httpAnlysis[i.DestinationAddress] += 1;
                        }
                    }
                }
            }
            foreach (KeyValuePair<string, int> k in httpAnlysis)
            {
                PieSeries pie = new PieSeries();
                pie.Title = k.Key;
                pie.Values = new ChartValues<int>(new int[]
                    { k.Value });
                pie.DataLabels = true;
                pie.LabelPoint = chartPoint =>
               string.Format("{0} ({1:P})", chartPoint.Y, chartPoint.Participation);
                this.graph.Series.Add(pie);
            }
        }
        private void _all()
        {
            Dictionary<string, int> httpAnlysis = new Dictionary<string, int>();
            foreach (var i in allitems)
            {
                if (!httpAnlysis.ContainsKey(i.DestinationAddress))
                {
                    httpAnlysis.Add(i.DestinationAddress, 1);
                }
                else
                {
                    httpAnlysis[i.DestinationAddress] += 1;
                }
            }
            foreach (KeyValuePair<string, int> k in httpAnlysis)
            {
                PieSeries pie = new PieSeries();
                pie.Title = k.Key;
                pie.Values = new ChartValues<int>(new int[]
                    { k.Value });
                pie.DataLabels = true;
                pie.LabelPoint = chartPoint =>
               string.Format("{0} ({1:P})", chartPoint.Y, chartPoint.Participation);
                this.graph.Series.Add(pie);
            }
        }
        private void Chart_OnDataClick(object sender, ChartPoint chartpoint)
        {
            var chart = (LiveCharts.Wpf.PieChart)chartpoint.ChartView;

            foreach (PieSeries series in chart.Series)
                series.PushOut = 0;

            var selectedSeries = (PieSeries)chartpoint.SeriesView;
            selectedSeries.PushOut = 8;
            sinfo.Text = selectedSeries.Title;
        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            if(is_http)
            {
                this.graph.Series.Clear();
                _all();
                is_http = false;
            }
            else
            {
                this.graph.Series.Clear();
                _http();
                is_http = true;
            }
        }
    }
}
