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


function [res_code, ICAO] = decode_icao ( packet )

    command = ['/bin/bash ', './icao.sh', ' | grep ICAO24'];
    
    filename = [tempname,'.dat'];
    
    command = ['/bin/bash ', './icao.sh ', filename, ' | grep ICAO24'];
    %filename='/tmp/trace.txt';
    
    fd = fopen(filename,'w');
    
    payload = bin2hex(sprintf('%1d',cell2mat(table2array(packet(1,6)))));
    
    for j=1:1:size(payload,2) 
        fprintf(fd,"%c", payload(j));
        if (mod(j,2) == 0)
            fprintf(fd," ");    
        end
    end
    
    fprintf(fd,"%d %.3f %.3f",  (table2array(packet(1,1))),  ... 
        (table2array(packet(1,7))),  (table2array(packet(1,8))));
    
    fprintf(fd,"0 0 0 0 0\n");
    fclose(fd);
    
    [status, cmdout] = system(command);
    
    c = strsplit(cmdout,' ');
    if (size(c,2) < 2)
        res_code = -1;
        ICAO = -1;
    else
    
        ICAO = c(3);
        if ( size(c,2) == 4 )        
            res_code = 0;
        else        
            res_code = -1;
        end
    end
    
    delete(filename);
    
end
