%   Copyright (C) Electrosense 2019
% 
%   This program is free software: you can redistribute it and/or modify
%   it under the terms of the GNU General Public License as published by
%   the Free Software Foundation, either version 3 of the License, or
%   (at your option) any later version.
% 
%   This program is distributed in the hope that it will be useful,
%   but WITHOUT ANY WARRANTY; without even the implied warranty of
%   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
%   GNU General Public License for more details.
% 
%   You should have received a copy of the GNU General Public License
%   along with this program.  If not, see http://www.gnu.org/licenses/. 
% 
%   Authors: Roberto Calvo-Palomino <roberto [dot] calvo [at] imdea [dot] org>


function [packet_detected] = uplink_demodulator(filename)

    th=0.04; th_ampl = 0.01;
    
    sprintf("Reading file %s ...", filename)
    fd = fopen(filename);
    fseek(fd, 0,'eof'); fd_len=ftell(fd);
    fclose(fd);

    % Preamble mask @4 MHz
    preamble=[1 1 1 1 1 1 0 0 0 0 0 0 0 0 0 0 1 1 1 1 1 1 0 0 0 0 0 0];

    %
    % Resample of the preamble if we work with 8 MHz
    %preamble=resample(preamble,2,1);

    % 4 MHz
    sampling_rate = 4e6;
    original_rate = 4e6;

    sps = sampling_rate / original_rate;
    short_packet_size = 56*sps;
    long_packet_size =112*sps;

    % Downsampling if it's needed.
    %preamble=resample(preamble,sps,1);

    preamble_len=4.75e-6/(1/sampling_rate);   % samples

    sync_pos=4.75e-6/(1/sampling_rate);       % samples -> 4.75 microsec.
    payload_pos = 5.25e-6/(1/sampling_rate);  % samples -> 5.25 microsec.

    packet_detected=table;

    % Slicing window configuration (IQ samples)
    slice_size=4e6*1; %slice_size=2e6; 
    over_size=300;

    fd = fopen(filename);

    % Iters to analyze the whole trace. Considerations:
    % - samples are float (divided by 4)
    % - loop manages IQ (divided by 2)

    size_float=4;
    file_samples = fd_len/size_float;

    read_pointers = [0:(slice_size*2-over_size):file_samples];

    samples_read=0;
    count=0;            


    for j=read_pointers

        b_slice = j; %samples

        if (b_slice*size_float + slice_size*size_float > fd_len) 
            read_len = b_slice*size_float + slice_size*size_float - fd_len;
        else
            read_len = slice_size;
        end

        fseek(fd,b_slice*size_float,'bof');
        raw = fread(fd,read_len*2,'float32');    
        slice = complex(raw(1:2:length(raw)), raw(2:2:length(raw)));

        samples_read = samples_read+read_len-(over_size*2);        
       
        % Preamble correlation
        amp_signal = abs(slice);    
        [acor, lag] = xcorr(abs(slice), preamble);
        acor = acor(end-length(slice)+1:end);            
                            
        i=1;
        while (i<=length(acor)-length(preamble))    

            if (acor(i) > th)
                
                % Manual check
                sum_area1 = mean(amp_signal(i : i + (3*round(sps)-1) ));
                sum_area2 = mean(amp_signal(i + (3*round(sps)) : i + (8*round(sps)-1)));
                sum_area3 = mean(amp_signal(i + (8*round(sps)) : i + (11*round(sps)-1)));
                sum_area4 = mean(amp_signal(i + (11*round(sps)) : i + (14*round(sps)-1)));

                max_preamble = max(amp_signal(i:i + (14*round(sps)-1)));
                 
                if (sum_area1 > th_ampl && sum_area3 > th_ampl && ...
                    sum_area1 > 1.5*sum_area2 && sum_area2 < sum_area3 && sum_area3 > 1.5*sum_area4 ) 

                    % high areas should be > than 2*low_areas                   
                    preamble_start = i;
                    
                    if isempty(packet_detected) || ...
                        (~ismember(b_slice+preamble_start, packet_detected{:,1}) && ...    
                        b_slice+preamble_start > packet_detected{end,1} && ...
                        (b_slice+preamble_start - packet_detected{end,1})> 70*sps )                        

                        % Detect the size of the packet                               
                        % Compute the mean amplitude for the long_packet_size (112)
                        payload_init = preamble_start + payload_pos;
                        if ( payload_init+long_packet_size > length(amp_signal) )
                            i=length(acor)+1;                       
                            continue;
                        end
                        mean_ampl = mean(amp_signal(payload_init:payload_init+long_packet_size));
                        max_ampl = max(amp_signal(payload_init:payload_init+long_packet_size));
                        min_ampl = min(amp_signal(payload_init:payload_init+long_packet_size));
                        
                        samples_above_mean = length(find(amp_signal(preamble_start+payload_pos:preamble_start+payload_pos+long_packet_size) >mean_ampl));

                        pkt_len = 0;
                        if (samples_above_mean >= short_packet_size*3/4 && samples_above_mean < short_packet_size*5/4)                    
                            pkt_len = 56;
                        elseif (samples_above_mean > long_packet_size*3/4 && samples_above_mean < long_packet_size*5/4)
                            pkt_len = 112;
                        else
                            sprintf('Packet length can not be estimated [56, 112] -> [ %d ] ', round(b_slice/2) + i);
                            %sprintf("%.3f | %.3f | %.3f\n", samples_above_mean, short_packet_size*3/4, short_packet_size*5/4)
                            i=i+1;                       
                            continue;
                        end                        
                        
                        % Sync Phase Reverse (SPR) detection;
                        % SPR should be at 4.75 microsec from the begining of
                        % the packet. We look in the margin of 1 microsec, that
                        % means [4.25 - 5.25] microseconds.
                        l_range = 4.25e-6/(1/sampling_rate);
                        h_range = 5.25e-6/(1/sampling_rate);

                        pkt_iq = complex(slice(preamble_start:preamble_start+payload_pos+pkt_len*sps-1+2*sps)); 
                        
                        % Check amplitude in the payload and preamble
                        % should be similar.
                        if ( max_ampl*1.5 < max_preamble)
                            i=i+1;
                            continue;
                        end                        

                        offset=2*sps;
                        delay_samp=sps;
                        mix_current = complex(pkt_iq(offset:end));
                        mix_delay = complex(pkt_iq(offset-delay_samp:end-delay_samp));                    
                        mixer_r = complex(complex(mix_current) .* conj(complex(mix_delay)));

                        phase_reverse = find(real(mixer_r(l_range:h_range)) < 0)+l_range; % remove -2

                        % Phase reverse was not found or more than one were
                        % found -> Most probabaly is not a mode-s uplink
                        % packet.

                        if (isempty(phase_reverse)) % || length(phase_reverse) >  )
                            sprintf('Sync Phase Reverse not detected, skip it! [ %d ] ', round(b_slice/2) + i)
                            i=i+1;
                            continue;
                        else
                            sprintf('Sync Phase Reverse detected at [ %d ] ', (phase_reverse(1)+offset)*(1/sampling_rate))
                        end
                        
                        

                        phase_reverse = phase_reverse(1); % remove + offset
                        phase_center = mean([angle(pkt_iq(phase_reverse)) angle(pkt_iq(phase_reverse-1))]);

                        % Hard check about the position of the sync phase
                        % reverse (SPR). SPR should be at 4.75 microseconds
                        % from the starting of the preamble. Margin of 0.5
                        % microseconds.
                        SPR_time = 4.75; SPR_margin = 0.25;


                        SPR_diff = abs(SPR_time-((1/sampling_rate)*phase_reverse)*1e6);
                        if ( SPR_diff > SPR_margin)
                            sprintf('Sync Phase Reverse detected but out of the margin (%.2f microsec [%.2f]), %d , skip it!',SPR_margin,SPR_diff,b_slice/2+preamble_start)                                                
                            i=i+1;                        
                            continue;
                        end

                        % Extract the bits from the payload by difference phase
                        % Multiply the conjugate of the delay version by 1 bit
                        % According to the sign -> assign '0' or '1' to symbol.  

                        % The series of chips starts 0.5 μs after the sync
                        % reversal ( at 4 MHz every sample is 0.25 microsec. )

                        payload_start = phase_reverse+2*sps;                        

                        % The last chip is followed by a 0.5-microsecond guard 
                        % interval whichprevents the trailing edge of P 6 from 
                        % interfering with the demodulation process.

                        pkt_iq = complex(slice(preamble_start:preamble_start+payload_start+pkt_len*sps+2*sps));
                       
                        mix_current = complex(pkt_iq(payload_start:payload_start+pkt_len*sps-1));

                        if (sps ~= 1)
                            mix_current = mean(reshape(mix_current,sps, length(mix_current)/sps)',sps);
                        end                    

                        mix_delay = complex(pkt_iq(payload_start-delay_samp:payload_start+pkt_len*sps-1-delay_samp));

                        if (sps ~=1)
                            mix_delay = mean(reshape(mix_delay,sps, length(mix_delay)/sps)',sps);
                        end
                        
                        % A phase reversal preceding a chip characterizes that chip as ONE. 
                        % No preceding phase reversal denotes a ZERO. 
                        mixer = mix_current .* conj(mix_delay);
                        symbols = zeros(length(mixer),1,'int32');
                        neg_sign = find(real(mixer)<0);
                        symbols(neg_sign) = 1; 
                       
                        UP_FACTOR=10;
                        pkt_iq_up = resample(pkt_iq,UP_FACTOR,1);
                        spr_pos = phase_reverse;
                        spr = ((spr_pos)*UP_FACTOR)/(sampling_rate*1e-6*UP_FACTOR);
                                              
                        % Compute SPR using upsampled signal
                        mpayload = pkt_iq_up((spr_pos-2)*UP_FACTOR:(spr_pos+1)*UP_FACTOR);                        
                        [value, indexOfSPR] = max(abs(diff(unwrap(angle(mpayload)))));
                                                                        
                        packet_aux = [];
                        found = false;   
                                                
                        
                        for pointer1=-5:1:5                            

                            spr2_sample = (indexOfSPR+(spr_pos-1)*UP_FACTOR);
                            spr2_sample = spr2_sample+pointer1;

                            % Compute the samples in the middle of the chips
                            idx = (spr2_sample + (UP_FACTOR/2):UP_FACTOR:length(pkt_iq_up));

                            samples = pkt_iq_up(idx(2:57));
                            delay_s = pkt_iq_up(idx(1:56));
                            mixer2 = samples .* conj(delay_s);
                            symbols2 = zeros(length(mixer2),1,'int32');
                            neg_sign2 = find(real(mixer2)<0);
                            symbols2(neg_sign2) = 1; 

                            % CRC is implemented is the decoder (python code)
                            Packet = struct();
                            Packet.timestamp_iq = round(b_slice/2) +preamble_start; % Review this!!
                            Packet.timestamp_micro = Packet.timestamp_iq / sampling_rate / 1e6;
                            Packet.length = pkt_len;
                            Packet.phase_reverse = phase_reverse;
                            Packet.UF = bin2dec(sprintf('%1d',symbols2(1:5)));
                            Packet.bits = {symbols2'};
                            Packet.amp_max = abs(max(pkt_iq));
                            Packet.amp_avg = abs(mean(pkt_iq));

                            [res_code, ICAO] = decode_icao(struct2table(Packet));

                            if (iscell(ICAO) && size(ICAO{1},2)==6)
                                Packet.ICAO = ICAO;
                            elseif (iscell(ICAO) && size(ICAO{1},2)==5)                             
                                Packet.ICAO =  strcat('0',ICAO{1});
                            else 
                                Packet.ICAO = {'000000'};% num2str(ICAO);
                            end                                                 

                            Packet.valid_ICAO = res_code;

                            
                            
                            Packet.amp_avg_icao = abs(mean(pkt_iq(end-25:end)));
                            Packet.phase_zero = size(find (abs(angle(pkt_iq(end-25:end))) < 0.2),1);
                            Packet.iq = {pkt_iq};

                            
                            
                            snr = 0;
                            if (preamble_start-50 > 0)
                                pkt_iq_SNR = complex(slice(preamble_start-50:preamble_start+payload_start+pkt_len*sps-1+2*sps));
                                snr = mean(abs(pkt_iq_SNR(51:end)))/mean(abs(pkt_iq_SNR(1:50)));                                                            
                            end

                            
                                                        
                            Packet.SNR = snr;
                            mth = max(abs(pkt_iq))*0.2;  low_idx = find(abs(pkt_iq) < mth); low_idx ( low_idx < 20 ) = [];
                            Packet.low_ampl_length = length(low_idx);
                            
                            if (pointer1==0)
                                packet_aux = Packet;
                            end
                            
                            if (Packet.valid_ICAO == 0 )                                
                                packet_detected=[packet_detected; struct2table(Packet)];
                                found = true;                                                               
                                
                                break;
                            end
                            
                        end
                        
                        if ~ found
                            Packet = packet_aux;                                                        
                            packet_detected=[packet_detected; struct2table(Packet)];                                                  
                            pointer1=0;
                        end
                        
                        
                        spr2 = ((indexOfSPR+(spr_pos-1+pointer1)*UP_FACTOR)) /(sampling_rate*1e-6*UP_FACTOR);                                                
                        spr2_sample = (indexOfSPR+(spr_pos-1)*UP_FACTOR);
                        spr2_sample = spr2_sample+pointer1;
                        % Compute the samples in the middle of the chips
                        idx = (spr2_sample + (UP_FACTOR/2):UP_FACTOR:length(pkt_iq_up));                                                                 
                                                                            
                    else
                        sprintf("Detected preamble duplicated, %d", b_slice/2+preamble_start)
                    end
                    % We should know at this point the size of the packet and
                    % then jump size_packet+1 to continue the preamble
                    % detection.
                    i=round(i+preamble_len+pkt_len*sps+1);
                    continue; 
                end                
            end

            i=i+1;

        end      

    end
    fclose(fd);	
    
    if (size(packet_detected,1) ~= 0 )
        packets_decoded_ok = size(find(cell2mat(table2cell((packet_detected(:,end-5)))) == 0),1);
        packets_error = size(find (strcmp(cell2mat(table2cell((packet_detected(:,end-6)))),"000000")),1); 
        packets_decoded_wrong = size(packet_detected,1) - packets_decoded_ok - packets_error;
        packets_detected_ok = packets_decoded_wrong + packets_decoded_ok;
        fprintf("====================================\n");
        fprintf('Packets detected: %d\n', size(packet_detected,1));
        fprintf('    * Packets error format:\t\t %d \t %.2f%%\n', packets_error, (packets_error*100)/size(packet_detected,1) )

        fprintf('Packets decoded: %d\n', packets_detected_ok);
        fprintf('    * Packets decoded wrong ICAO:\t %d \t %.2f%%\n', packets_decoded_wrong, (packets_decoded_wrong*100)/packets_detected_ok )
        fprintf('    * Packets decoded with ICAO:\t %d \t %.2f%%\n', packets_decoded_ok, (packets_decoded_ok*100)/packets_detected_ok )
        fprintf("====================================\n");
    end
    
    
end

