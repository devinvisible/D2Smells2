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


namespace D2Smells2
{
    partial class D2Smells2
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.rtbLog = new System.Windows.Forms.RichTextBox();
            this.btnToggleSniffing = new System.Windows.Forms.Button();
            this.cbInterface = new System.Windows.Forms.ComboBox();
            this.lblInterface = new System.Windows.Forms.Label();
            this.SuspendLayout();
            // 
            // rtbLog
            // 
            this.rtbLog.Anchor = ((System.Windows.Forms.AnchorStyles)((((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Bottom)
                        | System.Windows.Forms.AnchorStyles.Left)
                        | System.Windows.Forms.AnchorStyles.Right)));
            this.rtbLog.Font = new System.Drawing.Font("Lucida Console", 9.75F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.rtbLog.Location = new System.Drawing.Point(12, 41);
            this.rtbLog.Name = "rtbLog";
            this.rtbLog.Size = new System.Drawing.Size(773, 609);
            this.rtbLog.TabIndex = 0;
            this.rtbLog.Text = "";
            // 
            // btnToggleSniffing
            // 
            this.btnToggleSniffing.Location = new System.Drawing.Point(12, 12);
            this.btnToggleSniffing.Name = "btnToggleSniffing";
            this.btnToggleSniffing.Size = new System.Drawing.Size(75, 23);
            this.btnToggleSniffing.TabIndex = 1;
            this.btnToggleSniffing.Text = "Start Sniffing";
            this.btnToggleSniffing.UseVisualStyleBackColor = true;
            this.btnToggleSniffing.Click += new System.EventHandler(this.btnToggleSniffing_Click);
            // 
            // cbInterface
            // 
            this.cbInterface.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.cbInterface.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList;
            this.cbInterface.FormattingEnabled = true;
            this.cbInterface.Location = new System.Drawing.Point(451, 14);
            this.cbInterface.Name = "cbInterface";
            this.cbInterface.Size = new System.Drawing.Size(334, 21);
            this.cbInterface.TabIndex = 2;
            this.cbInterface.SelectedIndexChanged += new System.EventHandler(this.cbInterface_SelectedIndexChanged);
            // 
            // lblInterface
            // 
            this.lblInterface.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.lblInterface.AutoSize = true;
            this.lblInterface.Location = new System.Drawing.Point(396, 17);
            this.lblInterface.Name = "lblInterface";
            this.lblInterface.Size = new System.Drawing.Size(49, 13);
            this.lblInterface.TabIndex = 3;
            this.lblInterface.Text = "Interface";
            // 
            // D2Smells2
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(797, 662);
            this.Controls.Add(this.lblInterface);
            this.Controls.Add(this.cbInterface);
            this.Controls.Add(this.btnToggleSniffing);
            this.Controls.Add(this.rtbLog);
            this.Name = "D2Smells2";
            this.Text = "D2Smells2";
            this.Load += new System.EventHandler(this.D2Smells2_Load);
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion

        private System.Windows.Forms.RichTextBox rtbLog;
        private System.Windows.Forms.Button btnToggleSniffing;
        private System.Windows.Forms.ComboBox cbInterface;
        private System.Windows.Forms.Label lblInterface;
    }
}

