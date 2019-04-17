#include <stdio.h>
#include <stdlib.h>
#include <newt.h>


newtComponent r_intense, r_intense_udp, r_intense_tcp, r_quick, r_normal;

long slurp(char const* path, char **buf, int add_nul)
{
    FILE  *fp;
    size_t fsz;
    long   off_end;
    int    rc;

    /* Open the file */
    fp = fopen(path, "rb");
    if( NULL == fp ) {
        return -1L;
    }

    /* Seek to the end of the file */
    rc = fseek(fp, 0L, SEEK_END);
    if( 0 != rc ) {
        return -1L;
    }

    /* Byte offset to the end of the file (size) */
    if( 0 > (off_end = ftell(fp)) ) {
        return -1L;
    }
    fsz = (size_t)off_end;

    /* Allocate a buffer to hold the whole file */
    *buf = malloc( fsz+(int)add_nul );
    if( NULL == *buf ) {
        return -1L;
    }

    /* Rewind file pointer to start of file */
    rewind(fp);

    /* Slurp file into buffer */
    if( fsz != fread(*buf, 1, fsz, fp) ) {
        free(*buf);
        return -1L;
    }

    /* Close the file */
    if( EOF == fclose(fp) ) {
        free(*buf);
        return -1L;
    }

    if( add_nul ) {
        /* Make sure the buffer is NUL-terminated, just in case */
        buf[fsz] = '\0';
    }

    /* Return the file size */
    return (long)fsz;
}


char* ping(char addr[])
{	
	char *ping_result;
	newtPushHelpLine("  working ... ");
	newtRefresh();	

	char faddr[50];
    sprintf(faddr,"ping -c3 %s > stat_ping",addr);
	
    system(faddr);	
	slurp("stat_ping",&ping_result,1);
	newtPopHelpLine();
	return ping_result;	
}

char* scan(newtComponent ch)
{	
	char *scan_res;
	newtPushHelpLine("  Scanning ... ");
	newtRefresh();

	if(ch == r_intense)
	{
		system("nmap -T4 -A localhost > stat_scan");
	}else if( ch == r_intense_udp)
	{
		system("nmap -sS -sU -T4 -A localhost > stat_scan");		
	}else if(ch == r_intense_tcp)
	{
		system("nmap -p 1-65535 -T4 -A localhost > stat_scan");
	}else if(ch == r_quick)
	{
		system("nmap -T4 -F localhost > stat_scan");
	}else if(ch == r_normal)
	{
		system("nmap localhost > stat_scan");
	}else 
	{
		system(" echo \"UNKNOWN ERROR\" > stat_scan");
	}
		
	slurp("stat_scan",&scan_res,1);
	newtPopHelpLine();
	return scan_res;	
}

void main()
{
    newtInit();
    newtCls();

    unsigned int rows, cols;
	char *ping_addr, *ping_res, *scan_res;
    newtGetScreenSize(&cols, &rows);

    newtComponent main_form, ch_form, btn_ping, btn_sniff, btn_scan_ports, btn_exit;
	newtComponent ping_form, btn_start_ping, ent_ping_addr, btn_ping_cancel , tb_ping;
	newtComponent sniff_form, btn_start_sniff;
	newtComponent ports_form, btn_start_ports;
	newtComponent btn_sp_scan, sp_res, r_choice, btn_tb_cancel,tb_scan;
    
	btn_sp_scan = newtButton(5,rows-10, "Start Scan");
	r_intense= newtRadiobutton(5,5,"Intense Scan",0,0);
   	r_intense_udp = newtRadiobutton(5,7,"Intense Scan plus UDP",0,r_intense);
	r_intense_tcp  =newtRadiobutton(5,9,"Intense Scan plus TCP",0,r_intense_udp); 
	r_quick = newtRadiobutton(5,11,"Quick Scan",0,r_intense_tcp);
	r_normal =  newtRadiobutton(5,13,"Normal Scan",0,r_quick);
	btn_tb_cancel = newtButton(5,rows - 10 , "Cancel");
	tb_scan = newtTextbox(2, 1, 110, rows-18, NEWT_FLAG_SCROLL);

    //main form buttons
    btn_ping = newtButton(5, 0, "Ping");
    btn_sniff = newtButton(5, 5, "Sniff");
    btn_scan_ports = newtButton(5, 10, "Scan Ports");
    btn_exit = newtButton(5, 15, "Exit");
    
	//ping form buttons
	ent_ping_addr = newtEntry(2,2,0,cols-40, (const char**) &ping_addr,0);
	btn_start_ping = newtCompactButton(cols-36, 2, "Ping");
	btn_ping_cancel = newtCompactButton(cols-27, 2, "Cancel");
	tb_ping= newtTextbox(2, 4, 100, 18, NEWT_FLAG_SCROLL);	

    //initialising forms
    main_form = newtForm(NULL,NULL,0);
	ping_form = newtForm(NULL,NULL,0);
	sniff_form = newtForm(NULL,NULL,0);
	ports_form = newtForm(NULL,NULL,0);
	sp_res = newtForm(NULL,NULL,0);
    
    newtFormAddComponents(main_form, btn_ping, btn_sniff, btn_scan_ports, btn_exit, NULL); 
	newtFormAddComponents(ping_form, ent_ping_addr, btn_start_ping, btn_ping_cancel, tb_ping, NULL);
	newtFormAddComponents(sniff_form, btn_ping, NULL);
	newtFormAddComponents(ports_form, r_intense,r_intense_udp, r_intense_tcp, r_quick, r_normal, btn_sp_scan, NULL);
	newtFormAddComponents(sp_res,tb_scan, btn_tb_cancel, NULL);
	//newtFormAddComponents(,NULL);   
 
    do
    {	
		newtOpenWindow(2,2,cols-5 ,rows-5,"Network Administrator Tool");
        ch_form = newtRunForm(main_form);

        if(ch_form == btn_ping)
        {
            newtPopWindow();
		    newtOpenWindow(2,2,cols-5 ,rows-5,"Ping");
		    ch_form = newtRunForm(ping_form);

			if(ch_form = btn_start_ping)
			{	
				ping_res = ping(ping_addr);
				newtTextboxSetText( tb_ping, ping_res );
				ch_form = newtRunForm(ping_form);
				free(ping_res);
			}
        } 
		else if(ch_form == btn_sniff)
		{
			newtPopWindow();
		    newtOpenWindow(2,2,cols-5 ,rows-5,"Capture Packets");
		    ch_form = newtRunForm(ping_form);	
		}
		else if( ch_form == btn_scan_ports )
		{
			newtPopWindow();
		    newtOpenWindow(2,2,cols-5 ,rows-5,"Scan localhost Ports");
		    ch_form = newtRunForm(ports_form);
			if(ch_form = btn_sp_scan)	
			{	
				r_choice = newtRadioGetCurrent(r_intense);
				scan_res = scan(r_choice);

				newtPopWindow();
			    newtOpenWindow(2,2,cols-5 ,rows-5,"Result");
				newtTextboxSetText(tb_scan,scan_res);

				ch_form = newtRunForm(sp_res);			
				free(scan_res);
			}
		} 
    
    }while(ch_form != btn_exit);    

    newtFinished(); 
}
