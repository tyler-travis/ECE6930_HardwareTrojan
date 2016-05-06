----------------------------------------------------------------------
----																					----
---- Basic DES Block Cypher IP Core											----
---- 																					----
---- Implementation of DES-56 ECB mode IP core.							----
---- 																					----
---- To Do: 																		----
---- - 																				----
---- 																					----
---- Author(s): 																	----
---- - Steven R. McQueen, srmcqueen@opencores.org 						----
---- 																					----
----------------------------------------------------------------------
---- 																					----
---- Copyright (C) 2003 Steven R. McQueen									----
---- 																					----
---- This source file may be used and distributed without 			----
---- restriction provided that this copyright statement is not 	----
---- removed from the file and that any derivative work contains 	----
---- the original copyright notice and the associated disclaimer. ----
---- 																					----
---- This source file is free software; you can redistribute it 	----
---- and/or modify it under the terms of the GNU Lesser General 	----
---- Public License as published by the Free Software Foundation; ----
---- either version 2.1 of the License, or (at your option) any 	----
---- later version. 																----
---- 																					----
---- This source is distributed in the hope that it will be 		----
---- useful, but WITHOUT ANY WARRANTY; without even the implied 	----
---- warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR 		----
---- PURPOSE. See the GNU Lesser General Public License for more 	----
---- details. 																		----
---- 																					----
---- You should have received a copy of the GNU Lesser General 	----
---- Public License along with this source; if not, download it 	----
---- from http://www.opencores.org/lgpl.shtml 							----
---- 																					----
----------------------------------------------------------------------
--
-- CVS Revision History
--
-- $Log: not supported by cvs2svn $
-- Revision 1.1.1.1  2003/10/20 03:51:08  srmcqueen
-- First Upload, working module
--
--

-- This module implements the DES 56-bit Key Block Cypher. It expects to receive the 64-bit
-- data block to be encrypted or decrypted on the indata bus, and the 64-bit key on the inKey
-- bus. When the DS signal is high, encryption/decryption begins.	If the DECIPHER signal is
-- low when the DS signal is raised, the operation will be encryption. If the DECIPHER signal
-- is high when the DS signal goes high, the operation will be decryption. With each clock 
-- cycle, one round of encryption is performed.	After 16 rounds, the resulting message block
-- is presented on the OUTDATA bus and the RDY signal is set high.
--
-- Comments, questions and suggestions may be directed to the author at srmcqueen@mcqueentech.com.

-- 2005/09/02
-- Optimized key handling
-- added optional signals, changed RDY to be low on reset 
-- Perttu Fagerlund


-- 2005/10/15
-- Added comments
-- Steven R. McQueen
--
--

LIBRARY ieee;
USE ieee.std_logic_1164.ALL;
USE ieee.numeric_std.all;

--  Uncomment the following lines to use the declarations that are
--  provided for instantiating Xilinx primitive components.
--library UNISIM;
--use UNISIM.VComponents.all;
ENTITY des56 IS
   PORT( 
      indata         : IN     std_logic_vector (0 TO 63);
      inkey          : IN     std_logic_vector (0 TO 63);
      outdata        : OUT    std_logic_vector (0 TO 63);
      decipher       : IN     std_logic;
      ds             : IN     std_logic;
      clk            : IN     std_logic;
      rst            : IN     std_logic;
      rdy_next_next_cycle : OUT    std_logic;	-- output will be ready in two clock cycles - optional signal
      rdy_next_cycle : OUT    std_logic;      -- output will be ready in one clock cycle - optional signal
      rdy            : OUT    std_logic       -- output is ready NOW
   );


END des56 ;

architecture des of des56 is
-- ***********************************************************
-- * The following attributes are useful in Xilinx ISE
-- * for debugging purposes. They have been commented
-- * out to permit logic optimization.
-- ***********************************************************
--attribute keep: string;
--attribute nodelay: string;
--attribute s: string;

--attribute nodelay of indata: signal is "true";
--attribute nodelay of inkey: signal is "true";
--attribute nodelay of decipher: signal is "true";
--attribute nodelay of ds: signal is "true";
--attribute nodelay of clk: signal is "true";
--attribute nodelay of rst: signal is "true";
--attribute nodelay of rdy: signal is "true";
--attribute nodelay of outdata: signal is "true";

--attribute s of indata: signal is "yes";
--attribute s of inkey: signal is "yes";
--attribute s of decipher: signal is "yes";
--attribute s of ds: signal is "yes";
--attribute s of clk: signal is "yes";
--attribute s of rst: signal is "yes";
--attribute s of rdy: signal is "yes";
--attribute s of outdata: signal is "yes";

--signal xclk: std_logic;
--attribute keep of xclk: signal is "true";

-- mykey and inmsg are inputs to the encryption round logic
-- they will get new values on each clock
-- outmsg is the result of the encryption round, it will become inmsg for the next round
-- there are 16 encryption rounds in DES
signal mykey: std_logic_vector(0 to 47); 
--attribute keep of mykey: signal is "true";
signal inmsg: std_logic_vector(0 to 63);
--attribute keep of inmsg: signal is "true";
signal outmsg: std_logic_vector(0 to 63);
--attribute keep of outmsg: signal is "true";

-- round counters. countup is used for encryption, countdown is for decryption
-- mycounter takes its value from countup or countdown
signal countup: integer range 0 to 16;
signal countdown: integer range 0 to 16;
signal mycounter: integer range 0 to 16;
--attribute keep of mycounter: signal is "true";

-- the decrypt register holds the decrypt/encrypt switch
signal decrypt: std_logic;
signal ready: std_logic;

-- **********************************************
-- * New key registers. 
-- **********************************************
signal  key_l : std_logic_vector(0 to 27);
signal  key_r : std_logic_vector(0 to 27);
signal  keylr : std_logic_vector(0 to 55);

-- ******************************************************************
-- * various work signals. I want most of them to be wires, but
-- * they may be registers or latches, depending on the synthesizer
-- ******************************************************************
	signal d: std_logic_vector(0 to 47);
	signal f: std_logic_vector(0 to 31);
	signal b1: std_logic_vector(0 to 5);
	signal b2: std_logic_vector(0 to 5);
	signal b3: std_logic_vector(0 to 5);
	signal b4: std_logic_vector(0 to 5);
	signal b5: std_logic_vector(0 to 5);
	signal b6: std_logic_vector(0 to 5);
	signal b7: std_logic_vector(0 to 5);
	signal b8: std_logic_vector(0 to 5);
	signal s1: std_logic_vector(0 to 3);
	signal s2: std_logic_vector(0 to 3);
	signal s3: std_logic_vector(0 to 3);
	signal s4: std_logic_vector(0 to 3);
	signal s5: std_logic_vector(0 to 3);
	signal s6: std_logic_vector(0 to 3);
	signal s7: std_logic_vector(0 to 3);
	signal s8: std_logic_vector(0 to 3);

begin

-- ***************************************************************************************************
-- * Route wires to copy the key value for the next encryption round
-- ***************************************************************************************************
   keylr <= key_l & key_r;
   mykey <= keylr(13) & keylr(16) & keylr(10) & keylr(23) & keylr(0) & keylr(4) & keylr(2) & keylr(27) & 
            keylr(14) & keylr(5) & keylr(20) & keylr(9) & keylr(22) & keylr(18) & keylr(11) & keylr(3) &
            keylr(25) & keylr(7) & keylr(15) & keylr(6) & keylr(26) & keylr(19) & keylr(12) & keylr(1) &
            keylr(40) & keylr(51) & keylr(30) & keylr(36) & keylr(46) & keylr(54) & keylr(29) & keylr(39) &
            keylr(50) & keylr(44) & keylr(32) & keylr(47) & keylr(43) & keylr(48) & keylr(38) & keylr(55) &
            keylr(33) & keylr(52) & keylr(45) & keylr(41) & keylr(49) & keylr(35) & keylr(28) & keylr(31);
            
   SetKey: process (clk, countup, decipher)
-- *********************************************************************************************
-- * New key management logic by Perttu Fagerlund
-- * On the first clock, the first round key is registered. Thereafter, the round key is simply
-- * shifted by the necessary number of bits. This saves more than 57% of the required register
-- * logic cells over the previous code, which directly registered all of the round keys at once.
-- *
-- * A very slight speed increase may be realized due to shorter signal paths in the final fit.
-- *
-- * Use the current value of COUNTUP to determine which round of encryption is next.
-- * Load the KEY_L and KEY_R registers with the appropriate round key value.
-- * Note that on the first pass, the round key is not available, and must be
-- *		loaded directly from the input signals. The correct value is determined by
-- *		the state of the DECIPHER signal.
-- *********************************************************************************************
	begin
		if rising_edge(clk) then
			case countup is
				when 0 =>
               if (decipher = '0') then
                  -- these are readily shifted left by one !
                  key_l <= inkey(48) & inkey(40) & inkey(32) & inkey(24) & inkey(16) & inkey(8) & inkey(0) &
                           inkey(57) & inkey(49) & inkey(41) & inkey(33) & inkey(25) & inkey(17) & inkey(9) & inkey(1) &
                           inkey(58) & inkey(50) & inkey(42) & inkey(34) & inkey(26) & inkey(18) & inkey(10) & inkey(2) &
                           inkey(59) & inkey(51) & inkey(43) & inkey(35) & inkey(56);
                  key_r <= inkey(54) & inkey(46) & inkey(38) & inkey(30) & inkey(22) & inkey(14) & inkey(6) &
                           inkey(61) & inkey(53) & inkey(45) & inkey(37) & inkey(29) & inkey(21) & inkey(13) & inkey(5) &
                           inkey(60) & inkey(52) & inkey(44) & inkey(36) & inkey(28) & inkey(20) & inkey(12) & inkey(4) &
                           inkey(27) & inkey(19) & inkey(11) & inkey(3) & inkey(62);
               else
                  key_l <= inkey(56) & inkey(48) & inkey(40) & inkey(32) & inkey(24) & inkey(16) & inkey(8) & inkey(0) &
                           inkey(57) & inkey(49) & inkey(41) & inkey(33) & inkey(25) & inkey(17) & inkey(9) & inkey(1) &
                           inkey(58) & inkey(50) & inkey(42) & inkey(34) & inkey(26) & inkey(18) & inkey(10) & inkey(2) &
                           inkey(59) & inkey(51) & inkey(43) & inkey(35);
                  key_r <= inkey(62) & inkey(54) & inkey(46) & inkey(38) & inkey(30) & inkey(22) & inkey(14) & inkey(6) &
                           inkey(61) & inkey(53) & inkey(45) & inkey(37) & inkey(29) & inkey(21) & inkey(13) & inkey(5) &
                           inkey(60) & inkey(52) & inkey(44) & inkey(36) & inkey(28) & inkey(20) & inkey(12) & inkey(4) &
                           inkey(27) & inkey(19) & inkey(11) & inkey(3);
               end if;
               
				when 1 =>
               if (decipher = '1') then
                  key_l(0 to 27) <= key_l(27) & key_l(0 to 26);
                  key_r(0 to 27) <= key_r(27) & key_r(0 to 26);
               else
                  key_l(0 to 27) <= key_l(1 to 27) & key_l(0);
                  key_r(0 to 27) <= key_r(1 to 27) & key_r(0);
               end if;
				when 2 =>
               if (decipher = '1') then
                  key_l(0 to 27) <= key_l(26 to 27) & key_l(0 to 25);
                  key_r(0 to 27) <= key_r(26 to 27) & key_r(0 to 25);
               else
                  key_l(0 to 27) <= key_l(2 to 27) & key_l(0 to 1);
                  key_r(0 to 27) <= key_r(2 to 27) & key_r(0 to 1);
               end if;
				when 3 =>
               if (decipher = '1') then
                  key_l(0 to 27) <= key_l(26 to 27) & key_l(0 to 25);
                  key_r(0 to 27) <= key_r(26 to 27) & key_r(0 to 25);
               else
                  key_l(0 to 27) <= key_l(2 to 27) & key_l(0 to 1);
                  key_r(0 to 27) <= key_r(2 to 27) & key_r(0 to 1);
               end if;
				when 4 =>
               if (decipher = '1') then
                  key_l(0 to 27) <= key_l(26 to 27) & key_l(0 to 25);
                  key_r(0 to 27) <= key_r(26 to 27) & key_r(0 to 25);
               else
                  key_l(0 to 27) <= key_l(2 to 27) & key_l(0 to 1);
                  key_r(0 to 27) <= key_r(2 to 27) & key_r(0 to 1);
               end if;
				when 5 =>
               if (decipher = '1') then
                  key_l(0 to 27) <= key_l(26 to 27) & key_l(0 to 25);
                  key_r(0 to 27) <= key_r(26 to 27) & key_r(0 to 25);
               else
                  key_l(0 to 27) <= key_l(2 to 27) & key_l(0 to 1);
                  key_r(0 to 27) <= key_r(2 to 27) & key_r(0 to 1);
               end if;
				when 6 =>
               if (decipher = '1') then
                  key_l(0 to 27) <= key_l(26 to 27) & key_l(0 to 25);
                  key_r(0 to 27) <= key_r(26 to 27) & key_r(0 to 25);
               else
                  key_l(0 to 27) <= key_l(2 to 27) & key_l(0 to 1);
                  key_r(0 to 27) <= key_r(2 to 27) & key_r(0 to 1);
               end if;
				when 7 =>
               if (decipher = '1') then
                  key_l(0 to 27) <= key_l(26 to 27) & key_l(0 to 25);
                  key_r(0 to 27) <= key_r(26 to 27) & key_r(0 to 25);
               else
                  key_l(0 to 27) <= key_l(2 to 27) & key_l(0 to 1);
                  key_r(0 to 27) <= key_r(2 to 27) & key_r(0 to 1);
               end if;
				when 8 =>
               if (decipher = '1') then
                  key_l(0 to 27) <= key_l(27) & key_l(0 to 26);
                  key_r(0 to 27) <= key_r(27) & key_r(0 to 26);
               else
                  key_l(0 to 27) <= key_l(1 to 27) & key_l(0);
                  key_r(0 to 27) <= key_r(1 to 27) & key_r(0);
               end if;
				when 9 =>
               if (decipher = '1') then
                  key_l(0 to 27) <= key_l(26 to 27) & key_l(0 to 25);
                  key_r(0 to 27) <= key_r(26 to 27) & key_r(0 to 25);
               else
                  key_l(0 to 27) <= key_l(2 to 27) & key_l(0 to 1);
                  key_r(0 to 27) <= key_r(2 to 27) & key_r(0 to 1);
               end if;
				when 10 =>
               if (decipher = '1') then
                  key_l(0 to 27) <= key_l(26 to 27) & key_l(0 to 25);
                  key_r(0 to 27) <= key_r(26 to 27) & key_r(0 to 25);
               else
                  key_l(0 to 27) <= key_l(2 to 27) & key_l(0 to 1);
                  key_r(0 to 27) <= key_r(2 to 27) & key_r(0 to 1);
               end if;
				when 11 =>
               if (decipher = '1') then
                  key_l(0 to 27) <= key_l(26 to 27) & key_l(0 to 25);
                  key_r(0 to 27) <= key_r(26 to 27) & key_r(0 to 25);
               else
                  key_l(0 to 27) <= key_l(2 to 27) & key_l(0 to 1);
                  key_r(0 to 27) <= key_r(2 to 27) & key_r(0 to 1);
               end if;
				when 12 =>
               if (decipher = '1') then
                  key_l(0 to 27) <= key_l(26 to 27) & key_l(0 to 25);
                  key_r(0 to 27) <= key_r(26 to 27) & key_r(0 to 25);
               else
                  key_l(0 to 27) <= key_l(2 to 27) & key_l(0 to 1);
                  key_r(0 to 27) <= key_r(2 to 27) & key_r(0 to 1);
               end if;
				when 13 =>
               if (decipher = '1') then
                  key_l(0 to 27) <= key_l(26 to 27) & key_l(0 to 25);
                  key_r(0 to 27) <= key_r(26 to 27) & key_r(0 to 25);
               else
                  key_l(0 to 27) <= key_l(2 to 27) & key_l(0 to 1);
                  key_r(0 to 27) <= key_r(2 to 27) & key_r(0 to 1);
               end if;
				when 14 =>
               if (decipher = '1') then
                  key_l(0 to 27) <= key_l(26 to 27) & key_l(0 to 25);
                  key_r(0 to 27) <= key_r(26 to 27) & key_r(0 to 25);
               else
                  key_l(0 to 27) <= key_l(2 to 27) & key_l(0 to 1);
                  key_r(0 to 27) <= key_r(2 to 27) & key_r(0 to 1);
               end if;
				when 15 =>
               if (decipher = '1') then
                  key_l(0 to 27) <= key_l(27) & key_l(0 to 26);
                  key_r(0 to 27) <= key_r(27) & key_r(0 to 26);
               else
                  key_l(0 to 27) <= key_l(1 to 27) & key_l(0);
                  key_r(0 to 27) <= key_r(1 to 27) & key_r(0);
               end if;
				when others =>
			end case;
		end if;

	end process SetKey;



-- **********************************************************************************************
-- * Load the message word for the next encryption round
-- * As in SetKey, the data must be taken from the input ports on the first round.
-- * For all other rounds, the data value is taken from the OUTMSG signal. This signal
-- *		is produced by combinatorial logic.
-- *
-- * The first round of this cycle can be the last round of the previous cycle. Output is
-- *		driven at this time.
-- **********************************************************************************************
	SetData: process (clk, countup, rst, ds)
		variable C17: std_logic_vector(1 to 64);
	begin
		if rst = '1' then
--			rdy <= '1';	-- Original implementation - rdy is set high at reset
			rdy <= '0';	-- Optional implementation - rdy is set low at reset
		elsif rising_edge(clk) then
			rdy <= '0';
			
			case countup is
				when 0 =>
					if ds = '1' then
				-- new data: clock INMSG values directly from input signal
						inmsg <= indata(57) & indata(49) & indata(41) & indata(33) & indata(25) & indata(17) & indata(9) & indata(1) &
							indata(59) & indata(51) & indata(43) & indata(35) & indata(27) & indata(19) & indata(11) & indata(3) &
							indata(61) & indata(53) & indata(45) & indata(37) & indata(29) & indata(21) & indata(13) & indata(5) &
							indata(63) & indata(55) & indata(47) & indata(39) & indata(31) & indata(23) & indata(15) & indata(7) &
							indata(56) & indata(48) & indata(40) & indata(32) & indata(24) & indata(16) & indata(8) & indata(0) &
							indata(58) & indata(50) & indata(42) & indata(34) & indata(26) & indata(18) & indata(10) & indata(2) &
							indata(60) & indata(52) & indata(44) & indata(36) & indata(28) & indata(20) & indata(12) & indata(4) &
							indata(62) & indata(54) & indata(46) & indata(38) & indata(30) & indata(22) & indata(14) & indata(6);
						rdy <= '0';		-- Manage the "Data ready" signal
					end if;
					if ready = '0' then		--ready is really a "crypto in progress" signal
					-- Copy previous round output message data into local wire
						C17(1 to 32) := outmsg(32 to 63);
						C17(33 to 64) := outmsg(0 to 31);
					
					-- clock output message data to output vector. C17 was not strictly required but it made things easier for me.
						outdata <= C17(40) & C17(8) & C17(48) & C17(16) & C17(56) & C17(24) & C17(64) & C17(32) &
									  C17(39) & C17(7) & C17(47) & C17(15) & C17(55) & C17(23) & C17(63) & C17(31) &
									  C17(38) & C17(6) & C17(46) & C17(14) & C17(54) & C17(22) & C17(62) & C17(30) &
									  C17(37) & C17(5) & C17(45) & C17(13) & C17(53) & C17(21) & C17(61) & C17(29) &
									  C17(36) & C17(4) & C17(44) & C17(12) & C17(52) & C17(20) & C17(60) & C17(28) &
									  C17(35) & C17(3) & C17(43) & C17(11) & C17(51) & C17(19) & C17(59) & C17(27) & 
									  C17(34) & C17(2) & C17(42) & C17(10) & C17(50) & C17(18) & C17(58) & C17(26) &
									  C17(33) & C17(1) & C17(41) & C17(9) & C17(49) & C17(17) & C17(57) & C17(25);
						rdy <= '1';	-- indicate that valid output is on the bus
					end if;
				when others =>
					inmsg <= outmsg;	-- clock previous round output into next round input vector
					rdy <= '0';	-- manage the "data ready" signal
			end case;
		end if;

	end process setdata;


-- *************************************************************
-- * This handles the READY signal and counts the counters
-- *************************************************************
	Control: process (clk, ready, ds, RST, countup)
	
	begin

		if RST = '1' then
		-- assign reset values
			ready <= '1';
			countup <= 0;
         rdy_next_cycle <= '0';
         rdy_next_next_cycle <= '0';

		elsif rising_edge(clk) then
         rdy_next_cycle <= '0';
         rdy_next_next_cycle <= '0';
			if ready = '1' then
				if ds = '1' then
				-- data is being accepted. Assign starting clock and Data Ready values
					ready <= '0';
					countup <= 1;
				end if;
			else
				if countup = 0 then
				-- if counter is cleared and no input data, then
				--    indicate that device is waiting for work
					if ds = '0' then
						ready <= '1';
					end if;
				elsif countup < 14 then
				-- for counter = 1-13, just increment the counter
					countup <= countup + 1;
            elsif countup < 15 then
				-- for counter = 14, increment the counter and
				--   indicate that data will be ready in two clocks
					countup <= countup + 1;
               rdy_next_next_cycle <= '1';               
				else
				-- for counter = 15, increment the counter and
				--   indicate that data will be ready on the next clock
					countup <= 0;
               rdy_next_cycle <= '1';
				end if;
			end if;
		end if;

	end process control;


-- Combinatorial Logic
--   all of this takes around 7-8ns. Is there a way to make it faster?
--
-- expand 32 bits of the message word to 48 bits, mix it with the round key, 
-- then load it into 6-bit indexes.
	b1 <= (inmsg(63) & inmsg(36) & inmsg(32 to 35)) xor (mykey(0) & mykey(5) & mykey(1 to 4));
	b2 <= (inmsg(35) & inmsg(40) & inmsg(36 to 39)) xor (mykey(6) & mykey(11) & mykey(7 to 10));
	b3 <= (inmsg(39) & inmsg(44) & inmsg(40 to 43)) xor (mykey(12) & mykey(17) & mykey(13 to 16));
	b4 <= (inmsg(43) & inmsg(48) & inmsg(44 to 47)) xor (mykey(18) & mykey(23) & mykey(19 to 22));
	b5 <= (inmsg(47) & inmsg(52) & inmsg(48 to 51)) xor (mykey(24) & mykey(29) & mykey(25 to 28));
	b6 <= (inmsg(51) & inmsg(56) & inmsg(52 to 55)) xor (mykey(30) & mykey(35) & mykey(31 to 34));
	b7 <= (inmsg(55) & inmsg(60) & inmsg(56 to 59)) xor (mykey(36) & mykey(41) & mykey(37 to 40));
	b8 <= (inmsg(59) & inmsg(32) & inmsg(60 to 63)) xor (mykey(42) & mykey(47) & mykey(43 to 46));

-- 8 select statements to look up 4-bit S Box values based on the 6-bit indexes.
	with b1 select
		s1 <= x"e" when "000000",
				x"4" when "000001",
				x"d" when "000010",
				x"1" when "000011",
				x"2" when "000100",
				x"f" when "000101",
				x"b" when "000110",
				x"8" when "000111",
				x"3" when "001000",
				x"a" when "001001",
				x"6" when "001010",
				x"c" when "001011",
				x"5" when "001100",
				x"9" when "001101",
				x"0" when "001110",
				x"7" when "001111",
				x"0" when "010000",
				x"f" when "010001",
				x"7" when "010010",
				x"4" when "010011",
				x"e" when "010100",
				x"2" when "010101",
				x"d" when "010110",
				x"1" when "010111",
				x"a" when "011000",
				x"6" when "011001",
				x"c" when "011010",
				x"b" when "011011",
				x"9" when "011100",
				x"5" when "011101",
				x"3" when "011110",
				x"8" when "011111",
				x"4" when "100000",
				x"1" when "100001",
				x"e" when "100010",
				x"8" when "100011",
				x"d" when "100100",
				x"6" when "100101",
				x"2" when "100110",
				x"b" when "100111",
				x"f" when "101000",
				x"c" when "101001",
				x"9" when "101010",
				x"7" when "101011",
				x"3" when "101100",
				x"a" when "101101",
				x"5" when "101110",
				x"0" when "101111",
				x"f" when "110000",
				x"c" when "110001",
				x"8" when "110010",
				x"2" when "110011",
				x"4" when "110100",
				x"9" when "110101",
				x"1" when "110110",
				x"7" when "110111",
				x"5" when "111000",
				x"b" when "111001",
				x"3" when "111010",
				x"e" when "111011",
				x"a" when "111100",
				x"0" when "111101",
				x"6" when "111110",
				x"d" when "111111",
				"XXXX" when others;
				 

	with b2 select
		s2 <= x"f" when "000000",
				x"1" when "000001",
				x"8" when "000010",
				x"e" when "000011",
				x"6" when "000100",
				x"b" when "000101",
				x"3" when "000110",
				x"4" when "000111",
				x"9" when "001000",
				x"7" when "001001",
				x"2" when "001010",
				x"d" when "001011",
				x"c" when "001100",
				x"0" when "001101",
				x"5" when "001110",
				x"a" when "001111",
				x"3" when "010000",
				x"d" when "010001",
				x"4" when "010010",
				x"7" when "010011",
				x"f" when "010100",
				x"2" when "010101",
				x"8" when "010110",
				x"e" when "010111",
				x"c" when "011000",
				x"0" when "011001",
				x"1" when "011010",
				x"a" when "011011",
				x"6" when "011100",
				x"9" when "011101",
				x"b" when "011110",
				x"5" when "011111",
				x"0" when "100000",
				x"e" when "100001",
				x"7" when "100010",
				x"b" when "100011",
				x"a" when "100100",
				x"4" when "100101",
				x"d" when "100110",
				x"1" when "100111",
				x"5" when "101000",
				x"8" when "101001",
				x"c" when "101010",
				x"6" when "101011",
				x"9" when "101100",
				x"3" when "101101",
				x"2" when "101110",
				x"f" when "101111",
				x"d" when "110000",
				x"8" when "110001",
				x"a" when "110010",
				x"1" when "110011",
				x"3" when "110100",
				x"f" when "110101",
				x"4" when "110110",
				x"2" when "110111",
				x"b" when "111000",
				x"6" when "111001",
				x"7" when "111010",
				x"c" when "111011",
				x"0" when "111100",
				x"5" when "111101",
				x"e" when "111110",
				x"9" when "111111",
				"XXXX" when others;

	with b3 select
		s3 <= x"a" when "000000",
				x"0" when "000001",
				x"9" when "000010",
				x"e" when "000011",
				x"6" when "000100",
				x"3" when "000101",
				x"f" when "000110",
				x"5" when "000111",
				x"1" when "001000",
				x"d" when "001001",
				x"c" when "001010",
				x"7" when "001011",
				x"b" when "001100",
				x"4" when "001101",
				x"2" when "001110",
				x"8" when "001111",
				x"d" when "010000",
				x"7" when "010001",
				x"0" when "010010",
				x"9" when "010011",
				x"3" when "010100",
				x"4" when "010101",
				x"6" when "010110",
				x"a" when "010111",
				x"2" when "011000",
				x"8" when "011001",
				x"5" when "011010",
				x"e" when "011011",
				x"c" when "011100",
				x"b" when "011101",
				x"f" when "011110",
				x"1" when "011111",
				x"d" when "100000",
				x"6" when "100001",
				x"4" when "100010",
				x"9" when "100011",
				x"8" when "100100",
				x"f" when "100101",
				x"3" when "100110",
				x"0" when "100111",
				x"b" when "101000",
				x"1" when "101001",
				x"2" when "101010",
				x"c" when "101011",
				x"5" when "101100",
				x"a" when "101101",
				x"e" when "101110",
				x"7" when "101111",
				x"1" when "110000",
				x"a" when "110001",
				x"d" when "110010",
				x"0" when "110011",
				x"6" when "110100",
				x"9" when "110101",
				x"8" when "110110",
				x"7" when "110111",
				x"4" when "111000",
				x"f" when "111001",
				x"e" when "111010",
				x"3" when "111011",
				x"b" when "111100",
				x"5" when "111101",
				x"2" when "111110",
				x"c" when "111111",
				"XXXX" when others;

	with b4 select
		s4 <= x"7" when "000000",
				x"d" when "000001",
				x"e" when "000010",
				x"3" when "000011",
				x"0" when "000100",
				x"6" when "000101",
				x"9" when "000110",
				x"a" when "000111",
				x"1" when "001000",
				x"2" when "001001",
				x"8" when "001010",
				x"5" when "001011",
				x"b" when "001100",
				x"c" when "001101",
				x"4" when "001110",
				x"f" when "001111",
				x"d" when "010000",
				x"8" when "010001",
				x"b" when "010010",
				x"5" when "010011",
				x"6" when "010100",
				x"f" when "010101",
				x"0" when "010110",
				x"3" when "010111",
				x"4" when "011000",
				x"7" when "011001",
				x"2" when "011010",
				x"c" when "011011",
				x"1" when "011100",
				x"a" when "011101",
				x"e" when "011110",
				x"9" when "011111",
				x"a" when "100000",
				x"6" when "100001",
				x"9" when "100010",
				x"0" when "100011",
				x"c" when "100100",
				x"b" when "100101",
				x"7" when "100110",
				x"d" when "100111",
				x"f" when "101000",
				x"1" when "101001",
				x"3" when "101010",
				x"e" when "101011",
				x"5" when "101100",
				x"2" when "101101",
				x"8" when "101110",
				x"4" when "101111",
				x"3" when "110000",
				x"f" when "110001",
				x"0" when "110010",
				x"6" when "110011",
				x"a" when "110100",
				x"1" when "110101",
				x"d" when "110110",
				x"8" when "110111",
				x"9" when "111000",
				x"4" when "111001",
				x"5" when "111010",
				x"b" when "111011",
				x"c" when "111100",
				x"7" when "111101",
				x"2" when "111110",
				x"e" when "111111",
				"XXXX" when others;

	with b5 select
		s5 <= x"2" when "000000",
				x"c" when "000001",
				x"4" when "000010",
				x"1" when "000011",
				x"7" when "000100",
				x"a" when "000101",
				x"b" when "000110",
				x"6" when "000111",
				x"8" when "001000",
				x"5" when "001001",
				x"3" when "001010",
				x"f" when "001011",
				x"d" when "001100",
				x"0" when "001101",
				x"e" when "001110",
				x"9" when "001111",
				x"e" when "010000",
				x"b" when "010001",
				x"2" when "010010",
				x"c" when "010011",
				x"4" when "010100",
				x"7" when "010101",
				x"d" when "010110",
				x"1" when "010111",
				x"5" when "011000",
				x"0" when "011001",
				x"f" when "011010",
				x"a" when "011011",
				x"3" when "011100",
				x"9" when "011101",
				x"8" when "011110",
				x"6" when "011111",
				x"4" when "100000",
				x"2" when "100001",
				x"1" when "100010",
				x"b" when "100011",
				x"a" when "100100",
				x"d" when "100101",
				x"7" when "100110",
				x"8" when "100111",
				x"f" when "101000",
				x"9" when "101001",
				x"c" when "101010",
				x"5" when "101011",
				x"6" when "101100",
				x"3" when "101101",
				x"0" when "101110",
				x"e" when "101111",
				x"b" when "110000",
				x"8" when "110001",
				x"c" when "110010",
				x"7" when "110011",
				x"1" when "110100",
				x"e" when "110101",
				x"2" when "110110",
				x"d" when "110111",
				x"6" when "111000",
				x"f" when "111001",
				x"0" when "111010",
				x"9" when "111011",
				x"a" when "111100",
				x"4" when "111101",
				x"5" when "111110",
				x"3" when "111111",
				"XXXX" when others;

	with b6 select
		s6 <= x"c" when "000000",
				x"1" when "000001",
				x"a" when "000010",
				x"f" when "000011",
				x"9" when "000100",
				x"2" when "000101",
				x"6" when "000110",
				x"8" when "000111",
				x"0" when "001000",
				x"d" when "001001",
				x"3" when "001010",
				x"4" when "001011",
				x"e" when "001100",
				x"7" when "001101",
				x"5" when "001110",
				x"b" when "001111",
				x"a" when "010000",
				x"f" when "010001",
				x"4" when "010010",
				x"2" when "010011",
				x"7" when "010100",
				x"c" when "010101",
				x"9" when "010110",
				x"5" when "010111",
				x"6" when "011000",
				x"1" when "011001",
				x"d" when "011010",
				x"e" when "011011",
				x"0" when "011100",
				x"b" when "011101",
				x"3" when "011110",
				x"8" when "011111",
				x"9" when "100000",
				x"e" when "100001",
				x"f" when "100010",
				x"5" when "100011",
				x"2" when "100100",
				x"8" when "100101",
				x"c" when "100110",
				x"3" when "100111",
				x"7" when "101000",
				x"0" when "101001",
				x"4" when "101010",
				x"a" when "101011",
				x"1" when "101100",
				x"d" when "101101",
				x"b" when "101110",
				x"6" when "101111",
				x"4" when "110000",
				x"3" when "110001",
				x"2" when "110010",
				x"c" when "110011",
				x"9" when "110100",
				x"5" when "110101",
				x"f" when "110110",
				x"a" when "110111",
				x"b" when "111000",
				x"e" when "111001",
				x"1" when "111010",
				x"7" when "111011",
				x"6" when "111100",
				x"0" when "111101",
				x"8" when "111110",
				x"d" when "111111",
				"XXXX" when others;

	with b7 select
		s7 <= x"4" when "000000",
				x"b" when "000001",
				x"2" when "000010",
				x"e" when "000011",
				x"f" when "000100",
				x"0" when "000101",
				x"8" when "000110",
				x"d" when "000111",
				x"3" when "001000",
				x"c" when "001001",
				x"9" when "001010",
				x"7" when "001011",
				x"5" when "001100",
				x"a" when "001101",
				x"6" when "001110",
				x"1" when "001111",
				x"d" when "010000",
				x"0" when "010001",
				x"b" when "010010",
				x"7" when "010011",
				x"4" when "010100",
				x"9" when "010101",
				x"1" when "010110",
				x"a" when "010111",
				x"e" when "011000",
				x"3" when "011001",
				x"5" when "011010",
				x"c" when "011011",
				x"2" when "011100",
				x"f" when "011101",
				x"8" when "011110",
				x"6" when "011111",
				x"1" when "100000",
				x"4" when "100001",
				x"b" when "100010",
				x"d" when "100011",
				x"c" when "100100",
				x"3" when "100101",
				x"7" when "100110",
				x"e" when "100111",
				x"a" when "101000",
				x"f" when "101001",
				x"6" when "101010",
				x"8" when "101011",
				x"0" when "101100",
				x"5" when "101101",
				x"9" when "101110",
				x"2" when "101111",
				x"6" when "110000",
				x"b" when "110001",
				x"d" when "110010",
				x"8" when "110011",
				x"1" when "110100",
				x"4" when "110101",
				x"a" when "110110",
				x"7" when "110111",
				x"9" when "111000",
				x"5" when "111001",
				x"0" when "111010",
				x"f" when "111011",
				x"e" when "111100",
				x"2" when "111101",
				x"3" when "111110",
				x"c" when "111111",
				"XXXX" when others;

	with b8 select
		s8 <= x"d" when "000000",
				x"2" when "000001",
				x"8" when "000010",
				x"4" when "000011",
				x"6" when "000100",
				x"f" when "000101",
				x"b" when "000110",
				x"1" when "000111",
				x"a" when "001000",
				x"9" when "001001",
				x"3" when "001010",
				x"e" when "001011",
				x"5" when "001100",
				x"0" when "001101",
				x"c" when "001110",
				x"7" when "001111",
				x"1" when "010000",
				x"f" when "010001",
				x"d" when "010010",
				x"8" when "010011",
				x"a" when "010100",
				x"3" when "010101",
				x"7" when "010110",
				x"4" when "010111",
				x"c" when "011000",
				x"5" when "011001",
				x"6" when "011010",
				x"b" when "011011",
				x"0" when "011100",
				x"e" when "011101",
				x"9" when "011110",
				x"2" when "011111",
				x"7" when "100000",
				x"b" when "100001",
				x"4" when "100010",
				x"1" when "100011",
				x"9" when "100100",
				x"c" when "100101",
				x"e" when "100110",
				x"2" when "100111",
				x"0" when "101000",
				x"6" when "101001",
				x"a" when "101010",
				x"d" when "101011",
				x"f" when "101100",
				x"3" when "101101",
				x"5" when "101110",
				x"8" when "101111",
				x"2" when "110000",
				x"1" when "110001",
				x"e" when "110010",
				x"7" when "110011",
				x"4" when "110100",
				x"a" when "110101",
				x"8" when "110110",
				x"d" when "110111",
				x"f" when "111000",
				x"c" when "111001",
				x"9" when "111010",
				x"0" when "111011",
				x"3" when "111100",
				x"5" when "111101",
				x"6" when "111110",
				x"b" when "111111",
				"XXXX" when others;


-- Munge the S Boxes, then mix with the other 32 bits of the message word
	outmsg(32 to 63) <= (s4(3) & s2(2) & s5(3) & s6(0) & s8(0) & s3(3) & s7(3) & s5(0) &
								 s1(0) & s4(2) & s6(2) & s7(1) & s2(0) & s5(1) & s8(2) & s3(1) &
								 s1(1) & s2(3) & s6(3) & s4(1) & s8(3) & s7(2) & s1(2) & s3(0) &
								 s5(2) & s4(0) & s8(1) & s2(1) & s6(1) & s3(2) & s1(3) & s7(0)) xor inmsg(0 to 31);

-- the first 32 bits of the round output are the last 32 bits of the round input.
	outmsg(0 to 31) <= inmsg(32 to 63);

end des;

