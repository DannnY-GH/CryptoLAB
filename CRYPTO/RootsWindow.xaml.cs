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
using static CRYPTO_MATH.Math;

namespace CRYPTO {
    public partial class RootsWindow : Window {
        public RootsWindow() {
            InitializeComponent();
            foreach (int g in generator(MainWindow.PARAM))
                lbG.Items.Add(g.ToString());
            lbCount.Content += lbG.Items.Count.ToString();
        }

        private void Button_Click(object sender, RoutedEventArgs e) {
            Hide();
        }
    }
}
