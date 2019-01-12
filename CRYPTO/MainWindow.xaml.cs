using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Numerics;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using static CRYPTO_MATH.Math;
using static CRYPTO_POLYALP.PolyAlpCiphers;
using static CRYPTO_PERMUTATION.PermutationCiphers;
using static CRYPTO_PUBLIC.PublicKeyCiphers;
using static CRYPTO_STREAM.StreamCiphers;
using static CRYPTO_SIGNATURE.DigitalSignature;
using static FILTERS.Filters;

namespace CRYPTO {
    public partial class MainWindow : Window {
        public static long PARAM;
        const int MODES = 8;
        enum Modes { RailFence = 0, Column, Vigener, Kasiski, LFSR, RC4, Elgamal, RSA_DS }
        Modes mainMode = Modes.RSA_DS;
        List<List<DockPanel>> panelGroups;
        public MainWindow() {
            InitializeComponent();
            panelGroups = new List<List<DockPanel>>();
            for (int i = 0; i < MODES; i++)
                panelGroups.Add(new List<DockPanel>());
            panelGroups[(int)Modes.RailFence].Add(pnlSingleKey);
            panelGroups[(int)Modes.Column].Add(pnlSingleKey);
            panelGroups[(int)Modes.Vigener].Add(pnlSingleKey);
            panelGroups[(int)Modes.Kasiski].Add(pnlSingleKey);
            panelGroups[(int)Modes.Kasiski].Add(pnlKasiskiTest);
            panelGroups[(int)Modes.LFSR].Add(pnlLFSRKey);
            panelGroups[(int)Modes.RC4].Add(pnlSingleKey);
            panelGroups[(int)Modes.Elgamal].Add(pnlElgamal);
            panelGroups[(int)Modes.RSA_DS].Add(pnlRSA_DS);
            panelGroups[(int)Modes.RSA_DS].Add(pnlRSA_DS_E_HASH);
            EnablePanelGroup(Modes.RSA_DS);
        }
        void EnablePanelGroup(Modes mode) {
            if (this.IsLoaded == false)
                return;
            for (int i = 0; i < MODES; i++) {
                foreach (DockPanel panel in panelGroups[i])
                    panel.Visibility = Visibility.Collapsed;
            }
            foreach (DockPanel panel in panelGroups[(int)mode])
                panel.Visibility = Visibility.Visible;
        }
        bool isFileSelected(ListBox listBox) {
            return !(listBox.Items.Count == 0 || listBox.SelectedIndex == -1);
        }
        private void FileGuide(ListBox listBox) {
            if (listBox.Items.Count == 0)
                MessageBox.Show("You have to ADD some FILE...", "ATTENTION!", MessageBoxButton.OK, MessageBoxImage.Warning);
            else if (listBox.SelectedIndex == -1) {
                MessageBox.Show("You have to SELECT some FILE...", "ATTENTION!", MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }
        private void btnAddFilesClick(object sender, RoutedEventArgs e) {
            OpenFileDialog openFileDialog = new OpenFileDialog();
            openFileDialog.Multiselect = true;
            if (openFileDialog.ShowDialog() == true)
                foreach (string fileName in openFileDialog.FileNames)
                    lbFiles.Items.Add(fileName);
        }
        void LoadDataInto(TextBox dest) {
            if (isFileSelected(lbFiles)) {
                string filePath = lbFiles.SelectedItem.ToString();
                switch (mainMode) {
                    case Modes.RailFence:
                    case Modes.Column:
                    case Modes.Vigener:
                    case Modes.Kasiski:
                    case Modes.RSA_DS:
                        dest.Text = File.ReadAllText(filePath, Encoding.GetEncoding(1251));
                        break;
                    case Modes.LFSR:
                        dest.Text = DisplayBinary(File.ReadAllBytes(filePath));
                        break;
                    case Modes.RC4:
                        dest.Text = DisplayDecimal(File.ReadAllBytes(filePath));
                        break;
                    default:
                        dest.Text = File.ReadAllText(filePath, Encoding.GetEncoding(1251));
                        break;
                }
                tbCipherText.Clear();
            }
        }
        private void btnLoadPlainTextClick(object sender, RoutedEventArgs e) {
            LoadDataInto(tbPlainText);
        }
        private void btnLoadCipherTextClick(object sender, RoutedEventArgs e) {
            LoadDataInto(tbCipherText);
        }
        const int BIN_DISP_AMT = 2048;
        private string DisplayBinary(byte[] data) {
            char[] ret = new char[BIN_DISP_AMT * 16];
            int pos = 0;
            for (int i = 0; i < Math.Min(BIN_DISP_AMT, data.Length); i++) {
                for (int j = 7; j >= 0; j--) {
                    if ((data[i] & (1 << j)) > 0)
                        ret[pos++] = '1';
                    else
                        ret[pos++] = '0';
                }
                ret[pos++] = ' ';
            }
            return new string(ret, 0, pos);
        }
        private string DisplayDecimal(byte[] data) {
            int DISP_AMT = Math.Min(2048, data.Length);
            string[] ret = new string[DISP_AMT];
            for (int i = 0; i < DISP_AMT; i++) {
                ret[i] = data[i].ToString().PadLeft(3, '0');
            }
            return String.Join(" ", ret);
        }
        private string DisplayFileStreamInShort(FileStream fs) {
            int DISP_AMT = Math.Min(2048, (int)fs.Length / 2);
            string[] ret = new string[DISP_AMT];
            uint chunk;
            for (int i = 0; i < DISP_AMT; i++) {
                chunk = (uint)(fs.ReadByte() << 8 | fs.ReadByte());
                ret[i] = chunk.ToString().PadLeft(5, '0');
            }
            return String.Join(" ", ret);
        }
        private string ComposeFileName(string fileName) {
            if (isFileSelected(lbFiles)) {
                string selectedFile = lbFiles.SelectedItem.ToString();
                fileName = Path.Combine(Path.GetDirectoryName(selectedFile), fileName) + Path.GetExtension(selectedFile);
            }
            else
                fileName += ".txt";
            return fileName;
        }
        private void SaveToFile(string data, string fileName) {
            StreamWriter sw = File.CreateText(ComposeFileName(fileName));
            sw.Write(tbCipherText.Text);
            sw.Close();
        }
        private void SaveToFile(byte[] data, string fileName) {
            File.WriteAllBytes(ComposeFileName(fileName), data);
        }
        private void btnEncryptClick(object sender, RoutedEventArgs e) {
            switch ((Modes)cbMode.SelectedIndex) {
                case Modes.RailFence: {
                        tbPlainText.Text = engAlphaFilter(tbPlainText.Text);
                        int d = Int32.Parse(tbKey.Text);
                        if (d > 1)
                            tbCipherText.Text = RailFenceEncode(tbPlainText.Text, d);
                        else
                            tbCipherText.Text = tbPlainText.Text;
                        SaveToFile(tbCipherText.Text, "ENCRYPTED");
                    }
                    break;
                case Modes.Column: {
                        tbPlainText.Text = engAlphaFilter(tbPlainText.Text);
                        tbCipherText.Text = ColumnMethodEncode(tbPlainText.Text, tbKey.Text);
                        SaveToFile(tbCipherText.Text, "ENCRYPTED");
                    }
                    break;
                case Modes.Vigener:
                case Modes.Kasiski: {
                        tbPlainText.Text = rusAlphaFilter(tbPlainText.Text);
                        tbCipherText.Text = VigenerEncode(tbPlainText.Text, tbKey.Text);
                        SaveToFile(tbCipherText.Text, "ENCRYPTED");
                    }
                    break;
                case Modes.LFSR: {
                        if (isFileSelected(lbFiles)) {
                            byte[] data = File.ReadAllBytes(lbFiles.SelectedItem.ToString());
                            tbKey.Text = tbKey.Text.PadLeft(LFSR_BIT_CAPACITY, '0');
                            Stopwatch sw = new Stopwatch();
                            sw.Start();
                            LFSREncode(ref data, tbKey.Text);
                            sw.Stop();
                            tbCipherText.Text = DisplayBinary(data);
                            MessageBox.Show("ELAPSED TIME: " + sw.Elapsed, "ATTENTION!", MessageBoxButton.OK, MessageBoxImage.Warning);
                            SaveToFile(data, "ENCRYPTED");
                        }
                    }
                    break;
                case Modes.RC4: {
                        if (isFileSelected(lbFiles)) {
                            byte[] data = File.ReadAllBytes(lbFiles.SelectedItem.ToString());
                            RC4Encrypt(ref data, tbKey.Text);
                            tbCipherText.Text = DisplayDecimal(data);
                            SaveToFile(data, "ENCRYPTED");
                        }
                        else
                            FileGuide(lbFiles);
                    }
                    break;
                case Modes.Elgamal: {
                        if (!isFileSelected(lbFiles)) {
                            FileGuide(lbFiles);
                            return;
                        }
                        FileStream inFs = new FileStream(lbFiles.SelectedItem.ToString(), FileMode.Open, FileAccess.Read);
                        long p, x, k;
                        if (tbP.Text.Length == 0 || tbX.Text.Length == 0 || tbK.Text.Length == 0)
                            MessageBox.Show("Parameter Fields Shouldn't Be Empty", "ATTENTION!", MessageBoxButton.OK, MessageBoxImage.Error);
                        else {
                            Int64.TryParse(tbP.Text, out p);
                            Int64.TryParse(tbX.Text, out x);
                            Int64.TryParse(tbK.Text, out k);
                            if (!ferma(p) || p <= 255 || p > 65535) {
                                MessageBox.Show("P Must Be PRIME and 255 < P < 65536", "ATTENTION", MessageBoxButton.OK, MessageBoxImage.Error);
                            }
                            else if (!(x > 1 && x < p - 1))
                                MessageBox.Show("X Must Be 1 < X < P-1", "ATTENTION", MessageBoxButton.OK, MessageBoxImage.Error);
                            else if (!(k > 1 && k < (p - 1)) || gcd(k, p - 1) != 1)
                                MessageBox.Show("K Must Be 1 < K < P-1 AND (k, p-1) = 1", "ATTENTION", MessageBoxButton.OK, MessageBoxImage.Error);
                            else {
                                string outFsName = ComposeFileName("ENCRYPTED");
                                FileStream outFs = new FileStream(outFsName, FileMode.Create, FileAccess.Write);
                                PARAM = p;
                                RootsWindow w1 = new RootsWindow();
                                w1.ShowDialog();
                                long g = Int64.Parse(w1.lbG.SelectedItem.ToString());
                                w1.Close();
                                ElgamalEncrypt(inFs, outFs, p, x, k, g);
                                inFs.Close();
                                outFs.Close();
                                inFs = new FileStream(outFsName, FileMode.Open, FileAccess.Read);
                                tbCipherText.Text = DisplayFileStreamInShort(inFs);
                                inFs.Close();
                            }
                        }
                    }
                    break;
                case Modes.RSA_DS: {
                        if (!isFileSelected(lbFiles)) {
                            FileGuide(lbFiles);
                            return;
                        }
                        if (tbRSA_P.Text.Length == 0 || tbRSA_Q.Text.Length == 0 || tbRSA_K.Text.Length == 0)
                            MessageBox.Show("Parameter Fields Shouldn't Be Empty", "ATTENTION!", MessageBoxButton.OK, MessageBoxImage.Error);
                        else {
                            BigInteger P = BigInteger.Parse(tbRSA_P.Text);
                            BigInteger Q = BigInteger.Parse(tbRSA_Q.Text);
                            BigInteger D = BigInteger.Parse(tbRSA_K.Text);
                            if (!BigIntFerma(P)) {
                                MessageBox.Show("P MUST be PRIME!", "ATTENTION", MessageBoxButton.OK, MessageBoxImage.Error);
                            }
                            else if (!BigIntFerma(Q)) {
                                MessageBox.Show("Q MUST be PRIME!", "ATTENTION", MessageBoxButton.OK, MessageBoxImage.Error);
                            }
                            else if (P == Q) {
                                MessageBox.Show("P SHOULD NOT be EQUAL to Q!", "ATTENTION", MessageBoxButton.OK, MessageBoxImage.Error);
                            }
                            else {
                                BigInteger r = P * Q;
                                BigInteger rCopy = r;
                                int bitDepth = 0;
                                while (rCopy > 0) {
                                    rCopy /= 2;
                                    bitDepth++;
                                }
                                if (bitDepth <= 160) {
                                    MessageBox.Show("Bit Capacity of P*Q SHOULD be > 160!\nActual is: " + bitDepth.ToString(), "ATTENTION", MessageBoxButton.OK, MessageBoxImage.Error);
                                    return;
                                }
                                if(BIGgcd(D, (Q-1)*(P-1)) != 1) {
                                    MessageBox.Show("P and D must be relatively prime!", "ATTENTION", MessageBoxButton.OK, MessageBoxImage.Error);
                                    return;
                                }
                                BigInteger fi_r = (P - 1) * (Q - 1);
                                BigInteger E = 0, y = 0;
                                BIGextgcd(D, fi_r, ref E, ref y);
                                tbRSA_E.Text = E.ToString();
                                tbRSA_R.Text = r.ToString();
                                FileStream inFs = new FileStream(lbFiles.SelectedItem.ToString(), FileMode.Open, FileAccess.Read);
                                BigInteger HASH = SHA1(inFs);
                                inFs.Close();
                                tbRSA_HASH.Text = HASH.ToString();
                                BigInteger S = BIGpowmod(HASH, D, r);
                                tbRSA_SIGN.Text = S.ToString();
                                //SAVE
                                string filePath = lbFiles.SelectedItem.ToString();
                                string outFileName = ComposeFileName(Path.GetFileNameWithoutExtension(filePath) + "-SIGNED");
                                File.Copy(filePath, outFileName, true);
                                File.AppendAllText(outFileName, " " + tbRSA_SIGN.Text);
                            }
                        }
                    }
                    break;
            }
        }
        enum SplitFSM { Process, ReadNum, Done }
        private void btnDecryptClick(object sender, RoutedEventArgs e) {
            switch ((Modes)cbMode.SelectedIndex) {
                case Modes.RailFence: {
                        tbCipherText.Text = engAlphaFilter(tbCipherText.Text);
                        int d = Int32.Parse(tbKey.Text);
                        tbKey.Text = numericFilter(tbKey.Text);
                        if (d > 1)
                            tbPlainText.Text = RailFenceDecode(tbCipherText.Text, d);
                        else
                            tbPlainText.Text = tbCipherText.Text;
                        SaveToFile(tbPlainText.Text, "DECRYPTED");
                    }
                    break;
                case Modes.Column: {
                        tbCipherText.Text = engAlphaFilter(tbCipherText.Text);
                        tbPlainText.Text = ColumnMethodDecode(tbCipherText.Text, tbKey.Text);
                        SaveToFile(tbPlainText.Text, "DECRYPTED");
                    }
                    break;
                case Modes.Vigener:
                case Modes.Kasiski: {
                        tbCipherText.Text = rusAlphaFilter(tbCipherText.Text);
                        tbPlainText.Text = VigenerDecode(tbCipherText.Text, tbKey.Text);
                        SaveToFile(tbPlainText.Text, "DECRYPTED");
                    }
                    break;
                case Modes.LFSR: {
                        if (!isFileSelected(lbFiles)) {
                            FileGuide(lbFiles);
                            return;
                        }
                        byte[] data = File.ReadAllBytes(lbFiles.SelectedItem.ToString());
                        tbKey.Text = tbKey.Text.PadLeft(LFSR_BIT_CAPACITY, '0');
                        Stopwatch sw = new Stopwatch();
                        sw.Start();
                        LFSREncode(ref data, tbKey.Text);
                        sw.Stop();
                        MessageBox.Show("ELAPSED TIME " + sw.Elapsed, "ATTENTION!", MessageBoxButton.OK, MessageBoxImage.Warning);
                        tbPlainText.Text = DisplayBinary(data);
                        SaveToFile(data, "DECRYPTED");
                    }
                    break;
                case Modes.RC4: {
                        if (!isFileSelected(lbFiles)) {
                            FileGuide(lbFiles);
                            return;
                        }
                        byte[] data = File.ReadAllBytes(lbFiles.SelectedItem.ToString());
                        RC4Encrypt(ref data, tbKey.Text);
                        tbPlainText.Text = DisplayDecimal(data);
                        SaveToFile(data, "DECRYPTED");
                    }
                    break;
                case Modes.Elgamal: {
                        if (!isFileSelected(lbFiles)) {
                            FileGuide(lbFiles);
                            return;
                        }
                        FileStream inFs = new FileStream(lbFiles.SelectedItem.ToString(), FileMode.Open, FileAccess.Read);
                        long p, x;
                        if (tbP.Text.Length == 0 || tbX.Text.Length == 0)
                            MessageBox.Show("Parameter Fields Shouldn't Be Empty", "ATTENTION!", MessageBoxButton.OK, MessageBoxImage.Error);
                        else {
                            Int64.TryParse(tbP.Text, out p);
                            Int64.TryParse(tbX.Text, out x);
                            if (!ferma(p) || p < 255 || p > 65535) {
                                MessageBox.Show("P Must Be PRIME and 255 < P < 65536", "ATTENTION", MessageBoxButton.OK, MessageBoxImage.Error);
                            }
                            else if (!(x > 1 && x < p - 1))
                                MessageBox.Show("X Must Be 1 < X < P-1", "ATTENTION", MessageBoxButton.OK, MessageBoxImage.Error);
                            else {
                                string outFsName = "DECRYPTED" + System.IO.Path.GetExtension(lbFiles.SelectedItem.ToString());
                                FileStream outFs = new FileStream(outFsName, FileMode.Create, FileAccess.Write);
                                ElgamalDecrypt(inFs, outFs, x, p);
                                inFs.Close();
                                outFs.Close();
                                inFs = new FileStream(outFsName, FileMode.Open, FileAccess.Read);
                                tbPlainText.Text = DisplayFileStreamInShort(inFs);
                                inFs.Close();
                            }
                        }
                    }
                    break;
                case Modes.RSA_DS: {
                        if (!isFileSelected(lbFiles)) {
                            FileGuide(lbFiles);
                            return;
                        }
                        if (tbRSA_E.Text.Length == 0 || tbRSA_R.Text.Length == 0) {
                            MessageBox.Show("You need R and E to verify signature...", "ATTENTION!", MessageBoxButton.OK, MessageBoxImage.Error);
                            return;
                        }
                        string filePath = lbFiles.SelectedItem.ToString();
                        FileStream inFs = new FileStream(lbFiles.SelectedItem.ToString(), FileMode.Open, FileAccess.Read);
                        string outFileName = System.IO.Path.Combine(System.IO.Path.GetDirectoryName(filePath), System.IO.Path.GetFileNameWithoutExtension(filePath) + "-CUT-OFF" + System.IO.Path.GetExtension(filePath));
                        FileStream outFs = new FileStream(outFileName, FileMode.Create, FileAccess.Write);
                        byte[] BUF = new byte[512];
                        int amt = 0;
                        int bt;
                        BigInteger SIGN = 0;
                        SplitFSM state = SplitFSM.Process;
                        while (state != SplitFSM.Done) {
                            switch (state) {
                                case SplitFSM.Process:
                                    bt = inFs.ReadByte();
                                    if (bt == ' ') {
                                        BUF[amt] = (byte)bt;
                                        amt++;
                                        state = SplitFSM.ReadNum;
                                    }
                                    else {
                                        outFs.WriteByte((byte)bt);
                                    }
                                    break;
                                case SplitFSM.ReadNum:
                                    bt = inFs.ReadByte();
                                    if (Char.IsDigit((char)bt)) {
                                        SIGN = SIGN * 10 + (BigInteger)Char.GetNumericValue((char)bt);
                                        BUF[amt] = (byte)bt;
                                        amt++;
                                    }
                                    else if (bt != -1) {
                                        outFs.Write(BUF, 0, amt);
                                        amt = 0;
                                        SIGN = 0;
                                        inFs.Position = inFs.Position - 1;
                                        state = SplitFSM.Process;
                                    }
                                    else
                                        state = SplitFSM.Done;
                                    break;
                            }
                        }
                        outFs.Close();
                        inFs.Close();
                        if (SIGN == 0) {
                            MessageBox.Show("WRONG SIGNATURE FORMAT", "ATTENTION!", MessageBoxButton.OK, MessageBoxImage.Warning);
                            return;
                        }
                        inFs = new FileStream(outFileName, FileMode.Open, FileAccess.Read);
                        BigInteger P = BigInteger.Parse(tbRSA_P.Text);
                        BigInteger Q = BigInteger.Parse(tbRSA_Q.Text);
                        BigInteger E = BigInteger.Parse(tbRSA_E.Text);
                        BigInteger SM = BIGpowmod(SIGN, E, P * Q);
                        BigInteger HM = SHA1(inFs);
                        inFs.Close();
                        File.Delete(outFileName);
                        string MSG;
                        if (SM == HM)
                            MSG = "APPROVED!\n\n";
                        else
                            MSG = "DISAPPROVED.\n\n";
                        MSG += "SIGNATURE: \n" + SIGN.ToString() + "\n\n";
                        MSG += "Sign M:\n" + "HEX:\n" + SM.ToString("X") + "\nDEC:\n" + SM.ToString() + "\n\n";
                        MSG += "Hash M:\n" + "HEX:\n" + HM.ToString("X") + "\nDEC:\n" + HM.ToString();
                        MessageBox.Show(MSG, "ATTENTION!", MessageBoxButton.OK, MessageBoxImage.Warning);
                    }
                    break;
            }
        }
        private void tbKeyTextChanged(object sender, TextChangedEventArgs e) {
            if (this.IsLoaded == false)
                return;
            switch ((Modes)cbMode.SelectedIndex) {
                case Modes.RailFence:
                    tbKey.Text = numericFilter(tbKey.Text);
                    break;
                case Modes.Column:
                    tbKey.Text = engAlphaFilter(tbKey.Text);
                    break;
                case Modes.Vigener:
                case Modes.Kasiski:
                    tbKey.Text = rusAlphaFilter(tbKey.Text);
                    break;
                case Modes.LFSR:
                    tbKey.Text = binaryFilter(tbKey.Text);
                    break;
                case Modes.RSA_DS:
                    tbRSA_K.Text = BigUintFilter(tbRSA_K.Text);
                    tbRSA_P.Text = BigUintFilter(tbRSA_P.Text);
                    tbRSA_Q.Text = BigUintFilter(tbRSA_Q.Text);
                    tbRSA_K.Select(tbRSA_K.Text.Length, 0);
                    tbRSA_Q.Select(tbRSA_Q.Text.Length, 0);
                    tbRSA_P.Select(tbRSA_P.Text.Length, 0);
                    break;
            }
        }
        private void btnKasiskiAnalyseClick(object sender, RoutedEventArgs e) {
            lbKeys.Items.Clear();
            tbCipherText.Text = rusAlphaFilter(tbCipherText.Text);
            string text = tbCipherText.Text;
            if (text.Length == 0)
                MessageBox.Show("Nothing to analyse...", "ATTENTION!", MessageBoxButton.OK, MessageBoxImage.Warning);
            else
                foreach (string key in KasiskiTest(text)) {
                    lbKeys.Items.Add(key);
                }
        }
        private void lbKasiskiKeysSelected(object sender, SelectionChangedEventArgs e) {
            if (lbKeys.SelectedIndex != -1)
                tbKey.Text = lbKeys.SelectedItem.ToString();
        }
        private void cbClosed(object sender, EventArgs e) {
            mainMode = (Modes)cbMode.SelectedIndex;
            EnablePanelGroup(mainMode);
        }
        private void cbModeSelectionChanged(object sender, SelectionChangedEventArgs e) {
            mainMode = (Modes)cbMode.SelectedIndex;
            EnablePanelGroup(mainMode);
        }
    }
}
