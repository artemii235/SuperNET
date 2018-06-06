/******************************************************************************
 * Copyright © 2014-2018 The SuperNET Developers.                             *
 *                                                                            *
 * See the AUTHORS, DEVELOPER-AGREEMENT and LICENSE files at                  *
 * the top-level directory of this distribution for the individual copyright  *
 * holder information and the developer policies on copyright and licensing.  *
 *                                                                            *
 * Unless otherwise agreed in a custom licensing agreement, no part of the    *
 * SuperNET software, including this file may be copied, modified, propagated *
 * or distributed except according to the terms contained in the LICENSE file *
 *                                                                            *
 * Removal or modification of this copyright notice is prohibited.            *
 *                                                                            *
 ******************************************************************************/

#include "iguana777.h"
#include "../crypto777/jpeg/jpeglib.h"

#define NUM_COMBINED 100

#define LEFTMARGIN 0
#define TIMEIND_PIXELS 256
#define NUM_ACTIVE_PIXELS (1024 - TIMEIND_PIXELS)
#define MAX_ACTIVE_WIDTH (NUM_ACTIVE_PIXELS + TIMEIND_PIXELS)
double Display_scale = 1.;
#define TITLEBAR_HEIGHT 24
#define MAX_USER_INTERFACE_BITMAPS 1	// not completely implemented yet
#define DP_FULLSCREEN 0
#define DP_HALFSCREENV 1
#define DP_HALFSCREENH 2
#define DP_QUARTERSCREEN 3
#define DP_SCREEN8 4
#define DP_TOPSLICE 5
#define DP_TOPSLICE2 6
#define DP_64SCREEN 7
#define LEFTMARGIN 0
#define SCREENCLUMPSIZE 8
#define MAX_WEEKIND NUM_WEEKINDS


struct bq_info
{
	float tmpbuf[IGUANA_WIDTH];
	float linebuf[IGUANA_WIDTH];
	uint32_t *bitmap;
	float lastval,scale;
	
	int32_t jdatetime,timewindow,timescale,firstjdatetime;
	int32_t rowwidth,color;
	uint16_t height,width,blendflag,pad;
};

struct display_template
{
	char java_bitmap_fname[512];
	char title[128],lasttitle[128];	// only 128 bytes gets displayed
	uint32_t *java_bitmap;
	void *vp;
	struct bq_info fullscreen;
	struct bq_info sixtyfourscreen[64];
	struct bq_info halfscreenV[2],halfscreenH[2];
	struct bq_info quarterscreen[4];
	struct bq_info screenx8[8];
	struct bq_info topslice;
	struct bq_info topslice2;
	int32_t chartheight,windheight,rowwidth,updated;
	int32_t microsleep,firstjdatetime,type,margin;
	int32_t clumpsize,pad1,pad2,pad3;
};
struct display_template *DISPLAY;
double Display_shift=1.;
int32_t Display_pause,Display_j,Display_k,Display_contractnum;
int32_t JDATA_end_jdatetime,JDATA_first_jdatetime,Server2_weekind,Parsed_jdatetime,Parsed_jdatetimes[NUM_COMBINED+1];
int32_t Parsed_weekinds[NUM_COMBINED+1],paused_Parsed_jdatetimes[NUM_COMBINED+1],SharedBitmapDisplay_process;
int32_t Display_mousex,Display_mousey,Display_mouse_button,Nodisplay;
uint32_t *Display_bitmap,*Display_bitmaps[NUM_COMBINED+1];
double Latestbids[NUM_COMBINED+1],Latestasks[NUM_COMBINED+1];
int32_t Last_keypress_time,Disable_currency_display,Invert_currency_display,Display_mode=1;
uint64_t Reloadflag;
//struct wbits State_wbits,Parsed_wbits,Parsedbits[NUM_COMBINED+1],Processedbits[NUM_COMBINED+1],Processed_wbits,Trade_wbits,Feedback_wbits;

void gen_ppmfile(char *fname,int32_t binaryflag,uint8_t *bitmap,int32_t width,int32_t height)
{
    int32_t x,j,red,green,blue;
    FILE *fp;
    /*
     Each PPM image consists of the following:
     
     A "magic number" for identifying the file type. A ppm image's magic number is the two characters "P6".
     Whitespace (blanks, TABs, CRs, LFs).
     A width, formatted as ASCII characters in decimal.
     Whitespace.
     A height, again in ASCII decimal.
     Whitespace.
     The maximum color value (Maxval), again in ASCII decimal. Must be less than 65536 and more than zero.
     A single whitespace character (usually a newline).
     A raster of Height rows, in order from top to bottom. Each row consists of Width pixels, in order from left to right. Each pixel is a triplet of red, green, and blue samples, in that order. Each sample is represented in pure binary by either 1 or 2 bytes. If the Maxval is less than 256, it is 1 byte. Otherwise, it is 2 bytes. The most significant byte is first.
     */
    if ( (fp= fopen(fname,"wb")) != 0 )
    {
        fprintf(fp,"P6 %d %d 255\n",width,height);
        for (j=0; j<height; j++)
            for (x=0; x<width; x++)
            {
                red = *bitmap++, green = *bitmap++, blue = *bitmap++;
                if ( binaryflag != 0 )
                {
                    fputc(red & 0xff,fp);
                    fputc(green & 0xff,fp);
                    fputc(blue & 0xff,fp);
                } else fprintf(fp,"%d %d %d\n",red,green,blue);
            }
        fclose(fp);
    }
}

void gen_jpegfile(char *fname,int32_t quality,uint8_t *bitmap,int32_t width,int32_t height)
{
#ifdef later
    struct jpeg_compress_struct cinfo;
    struct jpeg_error_mgr jerr;
    FILE * outfile;		/* target file */
    JSAMPROW row_pointer[1];	/* pointer to JSAMPLE row[s] */
    int row_stride;		/* physical row width in image buffer */
    cinfo.err = jpeg_std_error(&jerr);
    jpeg_create_compress(&cinfo);
    if ( (outfile= fopen(fname,"wb")) == NULL)
    {
        fprintf(stderr, "can't open %s\n", fname);
        iguana_exit(0,0);
    }
    jpeg_stdio_dest(&cinfo, outfile);
    cinfo.image_width = width; 	/* image width and height, in pixels */
    cinfo.image_height = height;
    cinfo.input_components = 3;		/* # of color components per pixel */
    cinfo.in_color_space = JCS_RGB; 	/* colorspace of input image */
    jpeg_set_defaults(&cinfo);
    jpeg_set_quality(&cinfo, quality, TRUE /* limit to baseline-JPEG values */);
    jpeg_start_compress(&cinfo, TRUE);
    row_stride = width * 3;	/* JSAMPLEs per row in image_buffer */
    while (cinfo.next_scanline < cinfo.image_height)
    {
        row_pointer[0] = &bitmap[cinfo.next_scanline * row_stride];
        (void) jpeg_write_scanlines(&cinfo, row_pointer, 1);
    }
    jpeg_finish_compress(&cinfo);
    fclose(outfile);
    jpeg_destroy_compress(&cinfo);
#endif
}

/*
int main()
{
    int i; unsigned char image[100][300][3];
    memset(image,0,sizeof(image));
    for (i=0; i<300; i++)
        image[50][i][0] = 0x55, image[50][i][1] = 0xaa, image[50][i][2] = 0xff;
    write_JPEG_file("test.jpg",50,image,300,100);
    return(0);
}*/

double _pairaved(double valA,double valB)
{
	if ( valA != 0. && valB != 0. )
		return((valA + valB) / 2.);
	else if ( valA != 0. ) return(valA);
	else return(valB);
}

double calc_loganswer(double pastlogprice,double futurelogprice)
{
	if ( fabs(pastlogprice) < .0000001 || fabs(futurelogprice) < .0000001 )
		return(0);
	return(10000. * (exp(futurelogprice - pastlogprice)-1.));
}

double _pairdiff(register double valA,register double valB)
{
	if ( valA != 0. && valB != 0. )
		return((valA - valB));
	else return(0.);
}

double balanced_ave(double buf[],int32_t i,int32_t width)
{
	register int32_t nonz,j; register double sum,price;
	nonz = 0;
	sum = 0.0;
	for (j=-width; j<=width; j++)
	{
		price = buf[i + j];
		if ( price != 0.0 )
		{
			sum += price;
			nonz++;
		}
	}
	if ( nonz != 0 )
		sum /= nonz;
	return(sum);
}

void buf_trioave(double dest[],double src[],int32_t n)
{
	register int32_t i,j,width = 3;
	for (i=0; i<128; i++)
		src[i] = 0;
	//for (i=n-width-1; i>width; i--)
	//	dest[i] = balanced_ave(src,i,width);
	//for (i=width; i>0; i--)
	//	dest[i] = balanced_ave(src,i,i);
	for (i=1; i<width; i++)
		dest[i] = balanced_ave(src,i,i);
	for (i=width; i<1024-width; i++)
		dest[i] = balanced_ave(src,i,width);
	dest[0] = _pairaved(dest[0],dest[1] - _pairdiff(dest[2],dest[1]));
	j = width-1;
	for (i=1024-width; i<1023; i++,j--)
		dest[i] = balanced_ave(src,i,j);
	if ( dest[1021] != 0. && dest[1021] != 0. )
		dest[1023] = ((2.0 * dest[1022]) - dest[1021]);
	else dest[1023] = 0.;
}

void smooth1024(double dest[],double src[],int32_t smoothiters)
{
	double smoothbufA[1024],smoothbufB[1024]; int32_t i;
	buf_trioave(smoothbufA,src,1024);
	for (i=0; i<smoothiters; i++)
	{
		buf_trioave(smoothbufB,smoothbufA,1024);
		buf_trioave(smoothbufA,smoothbufB,1024);
	}
	buf_trioave(dest,smoothbufA,1024);
}

float _calc_pricey(register double price,register double weekave)
{
	if ( price != 0. && weekave != 0. )
		return(.2 * calc_loganswer(weekave,price));
	else return(0.f);
}

float pixelwt(register int32_t color)
{
	return(((float)((color>>16)&0x0ff) + (float)((color>>8)&0x0ff) + (float)((color>>0)&0x0ff))/0x300);
}

int32_t pixel_ratios(uint32_t red,uint32_t green,uint32_t blue)
{
	float max;
	/*if ( red > green )
	 max = red;
	 else
	 max = green;
	 if ( blue > max )
	 max = blue;*/
	max = (red + green + blue);
	if ( max == 0. )
		return(0);
	if ( max > 0xff )
	{
		red = (uint32_t)(((float)red / max) * 0xff);
		green = (uint32_t)(((float)green / max) * 0xff);
		blue = (uint32_t)(((float)blue / max) * 0xff);
	}
	
	if ( red > 0xff )
		red = 0xff;
	if ( green > 0xff )
		green = 0xff;
	if ( blue > 0xff )
		blue = 0xff;
	return((red << 16) | (green << 8) | blue);
}

int32_t conv_yval_to_y(register float yval,register int32_t height)
{
	register int32_t y;
	height = (height>>1) - 2;
	y = (int32_t)-yval;
	if ( y > height )
		y = height;
	else if ( y < -height )
		y = -height;
	
	y += height;
	if ( y < 0 )
		y = 0;
	height <<= 1;
	if ( y >= height-1 )
		y = height-1;
	return(y);
}

uint32_t scale_color(uint32_t color,float strength)
{
	int32_t red,green,blue;
	if ( strength < 0. )
		strength = -strength;
	red = (color>>16) & 0xff;
	green = (color>>8) & 0xff;
	blue = color & 0xff;
	
	red = (int32_t)((float)red * (strength/100.f));
	green = (int32_t)((float)green * (strength/100.f));
	blue = (int32_t)((float)blue * (strength/100.f));
	if ( red > 0xff )
		red = 0xff;
	if ( green > 0xff )
		green = 0xff;
	if ( blue > 0xff )
		blue = 0xff;
	return((red<<16) | (green<<8) | blue);
}

uint32_t pixel_blend(uint32_t pixel,uint32_t color)//,int32_t groupsize)
{
	int32_t red,green,blue,sum,n,n2,groupsize = 1;
	float red2,green2,blue2,sum2;
	if ( color == 0 )
		return(pixel);
	if ( pixel == 0 )
	{
		return((1<<24) | scale_color(color,100.f/(float)groupsize));
	}
	n = (pixel>>24) & 0xff;
	if ( n == 0 )
		n = 1;
	pixel &= 0xffffff;
	red = (pixel>>16) & 0xff;
	green = (pixel>>8) & 0xff;
	blue = pixel & 0xff;
	sum = red + green + blue;
	
	n2 = (color>>24) & 0xff;
	if ( n2 == 0 )
		n2 = 1;
	red2 = ((float)((color>>16) & 0xff)) / groupsize;
	green2 = ((float)((color>>8) & 0xff)) / groupsize;
	blue2 = ((float)(color & 0xff)) / groupsize;
	sum2 = (red2 + green2 + blue2);
	
	//printf("gs %d (%d x %d,%d,%d: %d) + (%d x %.1f,%.1f,%.1f: %.1f) = ",groupsize,n,red,green,blue,sum,n2,red2,green2,blue2,sum2);
	red = (uint32_t)(((((((float)red / (float) sum) * n) + (((float)red2 / (float) sum2) * n2)) / (n+n2)) * ((sum+sum2)/2)));
	green = (uint32_t)(((((((float)green / (float) sum) * n) + (((float)green2 / (float) sum2) * n2)) / (n+n2)) * ((sum+sum2)/2)));
	blue = (uint32_t)(((((((float)blue / (float) sum) * n) + (((float)blue2 / (float) sum2) * n2)) / (n+n2)) * ((sum+sum2)/2)));
	
	n += n2;
	if ( n > 0xff )
		n = 0xff;
	///printf("%x (%d,%d,%d) ",color,red,green,blue);
	color = (n<<24) | pixel_ratios(red,green,blue);//pixel_overflow(&red,&green,&blue);
	
	//printf("%x (%d,%d,%d)\n",color,(color>>16)&0xff,(color>>8)&0xff,color&0xff);
	return(color);
}

void init_forex_colors(uint32_t *forex_colors)
{
	int32_t i;
	forex_colors[0] = 0x00ff00;
	forex_colors[1] = 0x0033ff;
	forex_colors[2] = 0xff0000;
	forex_colors[3] = 0x00ffff;
	forex_colors[4] = 0xffff00;
	forex_colors[5] = 0xff00ff;
	forex_colors[6] = 0xffffff;
	forex_colors[7] = 0xff8800;
	forex_colors[8] = 0xff88ff;
	for (i=9; i<16; i++)
		forex_colors[i] = pixel_blend(forex_colors[i-8],0xffffff);
}

int32_t is_primary_color(register uint32_t color)
{
    static uint32_t forex_colors[16];
	register int32_t i;
    if ( forex_colors[0] == 0 )
        init_forex_colors(forex_colors);
	for (i=0; i<8; i++)
		if ( color == forex_colors[i] )
			return(1);
	return(0);
}

void disp_yval(register int32_t color,register float yval,register uint32_t *bitmap,register int32_t x,register int32_t rowwidth,register int32_t height)
{
	register int32_t y;
	x += LEFTMARGIN;
	if ( x < 0 || x >= rowwidth )
		return;
	//y = conv_yval_to_y(yval,height/Display_scale) * Display_scale;
	y = conv_yval_to_y(yval * Display_scale,height);
	if ( 1 && is_primary_color(color) != 0 )
	{
		bitmap[y*rowwidth + x] = color;
		return;
	}
	//if ( pixelwt(color) > pixelwt(bitmap[y*rowwidth + x]) )
	bitmap[y*rowwidth + x] = pixel_blend(bitmap[y*rowwidth + x],color);
	return;
	//if ( is_primary_color(color) != 0 || (is_primary_color(bitmap[y*rowwidth+x]) == 0 && pixelwt(color) > pixelwt(bitmap[y*rowwidth + x])) )
	//	bitmap[y*rowwidth + x] = color;
}

void disp_yvalsum(register int32_t color,register float yval,register uint32_t *bitmap,register int32_t x,register int32_t rowwidth,register int32_t height)
{
    int32_t y,red,green,blue,dispcolor;
	x += LEFTMARGIN;
	if ( x < 0 || x >= rowwidth )
		return;
	y = conv_yval_to_y(yval * Display_scale,height);
	red = (color>>16) & 0xff;
	green = (color>>8) & 0xff;
	blue = color & 0xff;
    dispcolor = bitmap[y*rowwidth + x];
	red += (dispcolor>>16) & 0xff;
	green += (dispcolor>>8) & 0xff;
	blue += dispcolor & 0xff;
	bitmap[y*rowwidth + x] = pixel_ratios(red,green,blue);
}

void disp_dot(register float radius,register int32_t color,register float yval,register uint32_t *bitmap,register int32_t x,register int32_t rowwidth,register int32_t height)
{
	register float i,j,sq,val;
	if ( radius > 1 )
	{
		sq = radius * radius;
		for (i=-radius; i<=radius; i++)
		{
			for (j=-radius; j<=radius; j++)
			{
				val = ((j*j + i*i) / sq);
				if ( val <= 1. )
				{
					val = 1. - val;
					disp_yval(scale_color(color,(100 * val * val * val * val)),yval+j,bitmap,x+i,rowwidth,height);
				}
			}
		}
	}
	else disp_yval(color,yval,bitmap,x,rowwidth,height);
}

void horizline(int32_t calclogflag,int32_t rowwidth,int32_t height,uint32_t *bitmap,double rawprice,double ave)
{
    int32_t x;
    double yval;
    if ( calclogflag != 0 )
        yval = _calc_pricey(log(rawprice),log(ave));
    else yval = _calc_pricey(rawprice,ave);
    for (x=0; x<rowwidth; x++)
        disp_yval(0x888888,yval,bitmap,x,rowwidth,height);
}

void rescale_floats(float *line,int32_t width,double scale)
{
    int32_t i;
    for (i=0; i<width; i++)
        line[i] *= scale;
}

void rescale_doubles(double *line,int32_t width,double scale)
{
    int32_t i;
    for (i=0; i<width; i++)
        line[i] *= scale;
}

double _output_line(int32_t calclogflag,double ave,float *output,double *buf,int32_t n,int32_t color,uint32_t *bitmap,int32_t rowwidth,int32_t height)
{
    int32_t x,nonz = 0;
    double yval,val,aveabs = 0.;
    if ( ave == 0. )
        return(0.);
    if ( calclogflag != 0 )
        ave = log(ave);
    for (x=0; x<n; x++)
    {
        if ( (val= buf[x]) != 0 )
        {
            if ( calclogflag != 0 )
                val = log(buf[x]);
            if ( ave != 1. )
                yval = _calc_pricey(val,ave);
            else yval = val;
            printf("%f ",yval);
            if ( fabs(yval) > .0000000001 )
            {
                aveabs += fabs(yval);
                nonz++;
                if ( color != 0 )
                    disp_yval(color,yval,bitmap,x,rowwidth,height);
            }
        } else yval = 0.;
        output[x] = yval;
    }
    if ( nonz != 0 )
        aveabs /= nonz;
    return(aveabs);
    //
    //printf("ave %f rowwidth.%d\n",ave,rowwidth);
}

void output_line(int32_t calclogflag,double ave,float *buf,int32_t n,int32_t color,uint32_t *bitmap,int32_t rowwidth,int32_t height)
{
    double src[1024],dest[1024]; int32_t i;
    memset(src,0,sizeof(src));
    memset(dest,0,sizeof(dest));
    if ( (1) )
    {
        for (i=0; i<1024; i++)
            src[1023-i] = dest[1023-i] = buf[i];
        smooth1024(dest,src,3);
        for (i=0; i<1024; i++)
            src[1023-i] = dest[i];
    }
    else
    {
        for (i=0; i<1024; i++)
            src[i] = buf[i];
    }
    _output_line(calclogflag,ave,buf,src,1024,color,bitmap,rowwidth,height);
}

void set_bi_fields(register struct bq_info *bi,register int32_t color,register int32_t signalid,register int32_t contractnum,register int32_t jdatetime,register int32_t timewindow,register uint32_t *bitmap,register int32_t rowwidth,register int32_t width,register int32_t height)
{
	memset(bi,0,sizeof(*bi));
	bi->color = color;
	bi->jdatetime = jdatetime;
	bi->timewindow = timewindow;
	bi->bitmap = bitmap;
	bi->rowwidth = rowwidth;
	bi->width = width;
	bi->height = height;
}

void set_bi_jdatetime(register struct bq_info *bi,register int32_t endjdatetime)
{
	bi->timewindow = bi->timescale * bi->width;
	bi->jdatetime = (endjdatetime - bi->timewindow);
	//printf("%s <- %s - %d\n",jdatetime_str(bi->jdatetime),jdatetime_str2(endjdatetime),bi->timewindow);
}

void init_display_template(register struct display_template *dp,register uint32_t *bitmap)//,register int32_t topslice_height)
{
	register int32_t timewindow,rowwidth,width,height,jdatetime,i,j,topslice_height=0,signalid = 0;
	timewindow = 0;
	signalid = 0;
	jdatetime = 0;
	width = dp->rowwidth;
	rowwidth = width;
	height = dp->windheight;
	if ( topslice_height != 0 )
	{
		set_bi_fields(&dp->topslice,0x00ff00,signalid,-1,jdatetime,width*60,bitmap,rowwidth,width/2,topslice_height);
		set_bi_fields(&dp->topslice2,0x00ff00,signalid,-1,jdatetime,width*60,bitmap+(width/2)+1,rowwidth,width/2-1,topslice_height);
		bitmap += topslice_height*rowwidth;
		height -= topslice_height;
	}
	set_bi_fields(&dp->fullscreen,0x00ff00,signalid,-1,jdatetime,timewindow,bitmap,rowwidth,width,height);
	bitmap++;
	width -= 2;
	height -= 2;
	{
		int32_t x,upperleft,w,h;
		//width -= 14;
		//height -= 14;
		//bitmap += 14;
        w = ((width-16)/8);
        h = ((height-18)/8);
		for (i=0; i<8; i++)
		{
			for (j=0; j<8; j++)
			{
				upperleft = ((rowwidth * (h*i + i*2 + 1)) + (w*j + 2*j + 1));
				x = (int)(((unsigned long)&bitmap[upperleft] - (unsigned long)bitmap)/sizeof(int));
				//printf("%p %d sixtyfour[%d][%d] upperleft %d:%d, width %d, height %d\n",bitmap+upperleft,x,i,j,upperleft/rowwidth,upperleft%rowwidth,width/8,height/8);
				set_bi_fields(&dp->sixtyfourscreen[i*8 + j],0x00ff00,signalid,-1,jdatetime,timewindow,bitmap + upperleft,rowwidth,w,h);
				//dp->sixtyfourscreen[i*8 + j].permi = (i*8 + j);
			}
		}
		//width += 14;
		//height += 14;
		//bitmap -= 14;
	}
	set_bi_fields(&dp->halfscreenV[0],0x00ff00,signalid,-1,jdatetime,timewindow,bitmap,rowwidth,width/2,height);
	set_bi_fields(&dp->halfscreenV[1],0x00ff00,signalid,-1,jdatetime,timewindow,bitmap+(width/2)+1,rowwidth,width/2,height);
	set_bi_fields(&dp->halfscreenH[0],0x00ff00,signalid,-1,jdatetime,timewindow,bitmap,rowwidth,width,height/2);
	set_bi_fields(&dp->halfscreenH[1],0x00ff00,signalid,-1,jdatetime,timewindow,bitmap+(rowwidth * (height/2)),rowwidth,width,height/2);
	
	bitmap++;
	width -= 2;
	height -= 2;
	set_bi_fields(&dp->quarterscreen[0],0x00ff00,signalid,-1,jdatetime,timewindow,bitmap,rowwidth,width/2,height/2);
	set_bi_fields(&dp->quarterscreen[1],0x00ff00,signalid,-1,jdatetime,timewindow,bitmap+(width/2)+1,rowwidth,width/2,height/2);
	set_bi_fields(&dp->quarterscreen[2],0x00ff00,signalid,-1,jdatetime,timewindow,bitmap+(rowwidth * (height/2)),rowwidth,width/2,height/2);
	set_bi_fields(&dp->quarterscreen[3],0x00ff00,signalid,-1,jdatetime,timewindow,bitmap+(rowwidth * (height/2))+(width/2+1),rowwidth,width/2,height/2);
	
	bitmap++;
	width -= 2;
	height -= 2;
	set_bi_fields(&dp->screenx8[0],0x00ff00,signalid,-1,jdatetime,timewindow,bitmap,rowwidth,width/4,height/2);
	set_bi_fields(&dp->screenx8[1],0x00ff00,signalid,-1,jdatetime,timewindow,bitmap+(width/4),rowwidth,width/4,height/2);
	set_bi_fields(&dp->screenx8[2],0x00ff00,signalid,-1,jdatetime,timewindow,bitmap+(width/2)+1,rowwidth,width/4,height/2);
	set_bi_fields(&dp->screenx8[3],0x00ff00,signalid,-1,jdatetime,timewindow,bitmap+(3*width/4)+2,rowwidth,width/4,height/2);
	set_bi_fields(&dp->screenx8[4],0x00ff00,signalid,-1,jdatetime,timewindow,bitmap+(rowwidth * (height/2)),rowwidth,width/4,height/2);
	set_bi_fields(&dp->screenx8[5],0x00ff00,signalid,-1,jdatetime,timewindow,bitmap+(rowwidth * (height/2))+(width/4),rowwidth,width/4,height/2);
	set_bi_fields(&dp->screenx8[6],0x00ff00,signalid,-1,jdatetime,timewindow,bitmap+(rowwidth * (height/2))+(width/2+1),rowwidth,width/4,height/2);
	set_bi_fields(&dp->screenx8[7],0x00ff00,signalid,-1,jdatetime,timewindow,bitmap+(rowwidth * (height/2))+(3*width/4)+2,rowwidth,width/4,height/2);
}

struct display_template *create_display_template(register char *java_bitmap_fname,register int32_t chartwidth,register int32_t chartheight,register int32_t topslice_height,register int32_t microsleep)
{
	register struct display_template *display;
	display = malloc(sizeof(*display));
	memset(display,0,sizeof(*display));
	display->windheight = chartheight  + TITLEBAR_HEIGHT;
	display->chartheight = chartheight;
	display->rowwidth = chartwidth;
	strcpy(display->title,java_bitmap_fname);
	display->microsleep = microsleep;
	return(display);
}

struct bq_info *bi_selector(register struct display_template *dp,register int32_t sizesel,register int32_t slot)
{
	register struct bq_info *bi;
	switch ( sizesel )
	{
		case DP_FULLSCREEN:
			bi = &dp->fullscreen;
			break;
		case DP_HALFSCREENV:
			bi = &dp->halfscreenV[slot];
			break;
		case DP_HALFSCREENH:
			bi = &dp->halfscreenH[slot];
			break;
		case DP_QUARTERSCREEN:
			bi = &dp->quarterscreen[slot];
			break;
		case DP_SCREEN8:
			bi = &dp->screenx8[slot];
			break;
		case DP_TOPSLICE:
			bi = &dp->topslice;
			break;
		case DP_TOPSLICE2:
			bi = &dp->topslice2;
			break;
		case DP_64SCREEN:
			/*if ( (slot % 8) != 0 )
			 slot--;
			 else
			 slot += 7;*/
			bi = &dp->sixtyfourscreen[slot];
			break;
		default:
			return(0);
	}
	if ( bi->width == 0 || bi->height == 0 )
		return(0);
	return(bi);
}

void fill_bqinfo(register struct bq_info *bi,register int32_t color)
{
	register int32_t i;
	register uint32_t *src;
	src = bi->bitmap;
	for (i=0; i<bi->height; i++,src+=bi->rowwidth)
		memset(src,color,sizeof(*src)*bi->width);
}

int32_t draw_bqpixel(register uint32_t *bitmap,register int32_t color,register int32_t blendflag,register int32_t x,register float yval,register int32_t height,register int32_t rowwidth)
{
	register int32_t y;
	y = conv_yval_to_y(yval,height);
	bitmap += y*rowwidth + x;
	if ( blendflag != 0 )
		return(*bitmap = pixel_blend(*bitmap,color));
	else
		return(*bitmap = color);
}

void draw_bqbuf(register int32_t filter,register float scale,register int32_t color,register int32_t blendflag,register struct bq_info *bi,register float *buf,register int32_t firstx)
{
	register int32_t i,x,width,n;
	register float val,factor;
	width = bi->width;
	if ( buf == 0 )
	{
		for (x=0; x<width; x++)
			draw_bqpixel(bi->bitmap,color,blendflag,x,scale,bi->height,bi->rowwidth);
		return;
	}
	n = 0;
	factor = 0;
	if ( filter != 0. )
	{
		for (i=0; i<width; i++)
		{
			x = (i + firstx) % bi->width;
			if ( (val= buf[x]*scale)*filter >= 0 )
			{
				bi->linebuf[i] = val;
				factor += fabs(val);
				n++;
			}
		}
	}
	else
	{
		for (i=0; i<width; i++)
		{
			x = (i + firstx) % bi->width;
			if ( (val = buf[x] * scale) != 0. )
			{
				//val = xdisp_cbrtf(val);
				//printf("%f ",val);
				bi->linebuf[i] = val;
				factor += fabs(val);
				n++;
			}
		}
	}
	if ( n != 0 && factor > SMALLVAL )
	{
		//printf("factor %f, -> %f, width %d\n",factor,(factor / n) * bi->height * .2f,width);
		factor = (factor / n) * 2.;
		for (i=0; i<width; i++)
			draw_bqpixel(bi->bitmap,color,blendflag,i,bi->linebuf[i]*factor,bi->height,bi->rowwidth);
	}
}

void draw_bq_horiz(register float yval,register int32_t color,register struct bq_info *bi)
{
	register uint32_t i,y,width,*bitmap;
	y = conv_yval_to_y(yval,bi->height);
	//printf("horiz yval %f -> y %d, color %x\n",yval,y,color);
	width = bi->rowwidth;
	bitmap = bi->bitmap + y*bi->rowwidth;
	for (i=0; i<width; i++)
		*bitmap++ = color;
}

void draw_bq_vert(register int32_t x,register int32_t color,register struct bq_info *bi)
{
	register uint32_t *bitmap;
	register int32_t y,rowwidth;
	bitmap = bi->bitmap + x;
	rowwidth = bi->rowwidth;
	for (y=0; y<bi->height; y++,bitmap+=rowwidth)
		*bitmap = color;
}

void draw_rect(register int32_t color,register int32_t startx,register int32_t endx,register int32_t starty,register int32_t endy,register uint32_t *bitmap,register int32_t rowwidth)
{
	register int32_t y,j,width = (endx - startx + 1);
	bitmap += (starty*rowwidth) + startx;
	for (y=starty; y<=endy; y++,bitmap+=rowwidth)
	{
		for (j=0; j<width; j++)
			bitmap[j] = color;
	}
}

#ifdef refonly
void update_display(register struct bq_info *bi,register int32_t display_weekind,register int32_t contractnum,register int32_t margin,register int32_t clumpsize)
{
	int32_t zeroline = BOTTOM_LINE,zerolines[NUM_COMBINED];
	struct bq_info BI;
	unsigned char dispbits[NUM_COMBINED/8+1];
	float polarities[NUM_COMBINED];
	register uint32_t *bitmap;
	register double mainscale,scale;
	register int32_t weekind,startind,yoffset,endind,height,rowwidth,c;
	int32_t j,x,base,Parsedx,Processedx;
	memset(dispbits,0,sizeof(dispbits));
	if ( bi == 0 )
	{
		memset(&BI,0,sizeof(BI));
		BI.firstjdatetime = weekFIRSTJDATETIME;
		BI.height = IGUANA_HEIGHT;
		BI.width = IGUANA_WIDTH;
		BI.rowwidth = IGUANA_WIDTH;
		bi = &BI;
		bi->bitmap = Display_bitmaps[Display_contractnum];
	}
	bitmap = bi->bitmap;
	height = bi->height;
	rowwidth = bi->rowwidth;
	memset(bitmap,0,IGUANA_HEIGHT*IGUANA_WIDTH*sizeof(int));
	endind = display_weekind;
	//if ( display_weekind < NUM_ACTIVE_PIXELS+MAX_LOOKAHEAD )
	//	return;
	while ( 0 && (startind = endind - NUM_ACTIVE_PIXELS*clumpsize) < 0 )
	{
		Display_clumpsize = MIN(Display_clumpsize,(endind - startind)/NUM_ACTIVE_PIXELS);
		if ( Display_clumpsize < 1 )
		{
			Display_clumpsize = 1;
			break;
		}
		clumpsize = Display_clumpsize;
	}
	yoffset = 0;
	clumpsize = MAX(1,Display_clumpsize);
	memset(polarities,0,sizeof(polarities));
	mainscale = MAX(1,(24. / Display_clumpsize))/2;
	Parsedx = NUM_ACTIVE_PIXELS-1;
	Processedx = -1;
	//draw_mouserects(bitmap,rowwidth);
	for (c=0; c<NUM_COMBINED; c++)
	{
		zerolines[c] = zeroline;
		polarities[c] = 0.f;
	}
	polarities[contractnum] = 1.f;
	if ( contractnum <= NUM_COMBINED )
	{
		SETBIT(dispbits,contractnum);
		for (c=0; c<NUM_COMBINED; c++)
		{
			if ( contractnum >= NUM_CONTRACTS && c < 36 )
			{
				if ( c < NUM_CONTRACTS )
				{
					if ( Contract_base[c] == contractnum-NUM_CONTRACTS )
						polarities[c] = 1.f, SETBIT(dispbits,c);
					else if ( Contract_rel[c] == contractnum-NUM_CONTRACTS )
						polarities[c] = -1.f, SETBIT(dispbits,c);
				}
			}
		}
		//draw_bq_horiz(0-1,0x888888,bi);
		draw_bq_horiz(0,0x444444,bi);
		//draw_bq_horiz(0+1,0x888888,bi);
		draw_bq_horiz(BOTTOM_LINE+150,0x444444,bi);
		draw_bq_horiz(BOTTOM_LINE,0x888888,bi);
		draw_bq_horiz(TOP_LINE,0x888888,bi);
		draw_bq_horiz(TOP_LINE-150,0x444444,bi);
		
		draw_bq_horiz(0,0x444400,bi);
	}
	else
	{
		for (base=0; base<8; base++)
			SETBIT(dispbits,NUM_CONTRACTS+base);
		base = 0;
		zerolines[NUM_CONTRACTS+base++] = 600/2;
		zerolines[NUM_CONTRACTS+base++] = 425/2;
		zerolines[NUM_CONTRACTS+base++] = 250/2;
		zerolines[NUM_CONTRACTS+base++] = 75/2;
		zerolines[NUM_CONTRACTS+base++] = -75/2;
		zerolines[NUM_CONTRACTS+base++] = -250/2;
		zerolines[NUM_CONTRACTS+base++] = -425/2;
		zerolines[NUM_CONTRACTS+base++] = -600/2;
		for (c=0; c<28; c++)
		{
			polarities[c] = 1.f;
			zerolines[c] = zerolines[c % 8];
		}
		for (base=0; base<8; base++)
		{
			polarities[base+28] = 1.f;
			draw_bq_horiz(zerolines[base+28],scale_color(forex_colors[base],25),bi);
			weekind = display_weekind + (0 - NUM_ACTIVE_PIXELS)*clumpsize;
			
			disp_contractvals(weekind*60+59,(weekind-display_weekind),clumpsize,weekind,c,0,-1,bitmap,rowwidth,height);
			for (x=0; x<IGUANA_WIDTH; x++,weekind+=clumpsize)
			{
				//weekind = display_weekind + (x - NUM_ACTIVE_PIXELS)*clumpsize;
				if ( weekind < 64 )
					continue;
				if ( weekind > display_weekind+1024 )
					break;
				disp_contractvals(weekind*60+59,weekind-display_weekind,clumpsize,weekind,base+28,zerolines[base+28],x,bitmap,rowwidth,height);
			}
		}
	}
	for (c=0; c<=NUM_COMBINED; c++)
	{
		if ( c != Display_contractnum )
			continue;
		scale = mainscale;
		scale *= polarities[c];
		yoffset = zerolines[c];
		yoffset /= Display_scale;
		if ( c == contractnum )
		{
			weekind = display_weekind + (0 - NUM_ACTIVE_PIXELS)*clumpsize;
            //printf("weekind.%d MAX_LOOKAHEAD %d\n",weekind,MAX_LOOKAHEAD);
			if ( weekind < NUM_WEEKINDS-NUM_ACTIVE_PIXELS*clumpsize )
			{
                //printf("parsed %d, weekind.%d clumpsize.%d\n",display_weekind,weekind,clumpsize);
				disp_contractvals(weekind*60+59,weekind-display_weekind,clumpsize,weekind,c,0,-1,bitmap,rowwidth,height);
				for (x=0; x<IGUANA_WIDTH; x++,weekind+=clumpsize)
				{
					//printf("x.%d parsed %d, weekind.%d clumpsize.%d\n",x,display_weekind,weekind,clumpsize);
					//weekind = display_weekind + (x - NUM_ACTIVE_PIXELS)*clumpsize;
					//if ( weekind <= 1024 )
					//	continue;
					if ( weekind <= Processed_wbits.weekind && weekind+clumpsize <= Processed_wbits.weekind )
						Processedx = x;
					if ( weekind > display_weekind+1024 )
						break;
                    if ( weekind > TRADECONTAMINATION/60 )
                        disp_contractvals(weekind*60+59,weekind-display_weekind,clumpsize,weekind,c,0,x,bitmap,rowwidth,height);
				}
			}
		}
	}
	for (j=-height/Display_scale; j<height/Display_scale; j++)
	{
		//disp_yval(0x555555,j,bitmap,Parsedx+512/clumpsize,rowwidth,height);
		disp_yval(0x330000,j,bitmap,Parsedx+MAX_LOOKAHEAD,rowwidth,height);
		disp_yval(0x002200,j,bitmap,Parsedx,rowwidth,height);
		disp_yval(0x002200,j,bitmap,Parsedx - MAX_LOOKAHEAD,rowwidth,height);
		disp_yval(0x333333,j,bitmap,Parsedx - (TCLUMPSIZE*TIMEIND_PIXELS)/(clumpsize*60),rowwidth,height);
		disp_yval(0x333333,j,bitmap,IGUANA_WIDTH - 73,rowwidth,height);
		disp_yval(0x333333,j,bitmap,IGUANA_WIDTH - 13,rowwidth,height);
		/*if ( clumpsize < 20 )
         disp_yval(0x003300,j,bitmap,Parsedx - NNcontamination/clumpsize,rowwidth,height);
         if ( Processedx >= 0 )
         disp_yval(0x008800,j,bitmap,Processedx,rowwidth,height);
         */
		if ( j >= (TOP_LINE+125)/Display_scale || j <= (BOTTOM_LINE-135)/Display_scale )
		{
            int32_t i;
			for (i=1; i<24; i++)
			{
				if ( i*(60/clumpsize) < Parsedx )
					disp_yval(0x333333,j,bitmap,Parsedx - i*(60/clumpsize),rowwidth,height);
			}
		}
	}
}

void *display_loop(void *ptr)
{
	struct bq_info BI;
	register double aveprice;
	register int32_t c,tradechar,weeknum,jdatetime,actual_timeind,display_timeind,docid,pass,counter=0;
	register struct display_template *display;
	display = ptr;
	docid = weeknum = pass = jdatetime = -1;
	sleep(5);
	while ( Nodisplay != 0 )
		sleep(1);
	while ( 1 )
	{
		char title[BUFSIZE];
		char *tradeinfo_str(register int32_t contractnum,register int32_t jdatetime);
		char kstr[16];
		memset(&BI,0,sizeof(BI));
		BI.height = IGUANA_HEIGHT;
		BI.width = IGUANA_WIDTH;
		BI.rowwidth = IGUANA_WIDTH;
		BI.timescale = display->clumpsize;
		
		if ( Display_bitmaps[NUM_COMBINED] == 0 )
			Display_bitmaps[NUM_COMBINED] = alloc_aligned_buffer(sizeof(*Display_bitmaps[NUM_COMBINED]) * IGUANA_WIDTH * IGUANA_HEIGHT);
		if ( Display_bitmaps[Display_contractnum] == 0 )
			Display_bitmaps[Display_contractnum] = alloc_aligned_buffer(sizeof(*Display_bitmaps[Display_contractnum]) * IGUANA_WIDTH * IGUANA_HEIGHT);
		BI.bitmap = Display_bitmaps[NUM_COMBINED];
		if ( Parsed_weekinds[Display_contractnum] == 0 )
		{
			Parsed_weekinds[Display_contractnum] = Parsedbits[Display_contractnum].weekind;//1024+Display_clumpsize;//*1.5*NUM_ACTIVE_PIXELS;
			//Display_clumpsize = 750;
		}
		display->clumpsize = Display_clumpsize;
		BI.timewindow = BI.width*display->clumpsize;
		//Parsed_jdatetime = wbits_to_jdatetime(valid_wbits(parsed_weekind),0);
		//get_lockid(DISPLAY_LOCKID);
		actual_timeind = jdatetime_to_timeind(actual_gmt_jdatetime() + 0*dst_adjust(actual_gmt_jdatetime()));
		display_timeind = (Display_mode != 0) ? Parsed_wbits.weekind*60+Parsed_wbits.b.len : actual_timeind;//Processed_wbits.weekind;//Parsed_weekinds[Display_contractnum] : Processedbits[Display_contractnum].weekind;
		//printf("Parsed_wbits.weekind %d, actual_weekind %d| actual %d 1st %d\n",Parsed_wbits.weekind,actual_weekind,actual_gmt_jdatetime(),_FIRSTJDATETIME);
        update_display(&BI,display_timeind/60,Display_contractnum,LEFTMARGIN,SCREENCLUMPSIZE);
		
		sprintf(kstr,".d%d",Display_k);
		//sprintf(title,"%d %s R%d%c %s %7.6f %7.6f %s w%d %.3f |%s",counter,CONTRACTS[Display_contractnum],Display_clumpsize,jdatetime_str(wbits_to_jdatetime(valid_wbits(Parsed_weekinds[Display_contractnum]),0)),exp(Latestbids[Display_contractnum]),exp(Dispweekaves[Display_contractnum]),Display_pause!=0?"STOP":"",Parsed_weekinds[Display_contractnum],Display_scale,dispREQ_str(Display_REQ_selector));
		if ( Display_contractnum != NUM_COMBINED )
			aveprice = Lastprices[Display_contractnum];//_Quotes_aved(refc_to_c(Display_contractnum),actual_weekind*60-60,60);//_bufaved(&SVMS[c_to_refc(Display_contractnum)]->D->aveprices[display_weekind-8],8);
		//SVMS[Display_contractnum%NUM_COMBINED]->TS.pending-SVMS[Display_contractnum%NUM_COMBINED]->TS.gainsum
		//if ( Dispweekaves[Display_contractnum] == 0 )
		//	Dispweekaves[Display_contractnum] = _pairaved(Latestbids[Display_contractnum],Latestasks[Display_contractnum]);
        tradechar = ' ';
        if ( Display_contractnum < 36 )
        {
            if ( SVMS[Display_contractnum]->TS.dir > 0 )
                tradechar = '+';
            else if ( SVMS[Display_contractnum]->TS.dir < 0 )
                tradechar = '-';
        }
        sprintf(title,"%d %c%s.%s R%d%c %8.6f %8.6f %s w%d lag.%d %11.7f %s t%d",counter,tradechar,CONTRACTS[Display_contractnum],Display_contractnum==NUM_COMBINED?CURRENCIES[Display_k]:"",Display_clumpsize,'a'+Display_j,exp(aveprice),exp(Dispweekaves[Display_contractnum]),Display_pause!=0?"STOP":"",display_timeind/60,actual_timeind - display_timeind,Display_scale,jdatetime_str(actual_gmt_jdatetime()),actual_timeind);//,Disp_masizes[0][0],Disp_masizes[0][1],Disp_masizes[1][0],Disp_masizes[1][1]);//,dispREQ_str(Display_REQ_selector));
		strncpy(display->title,title,sizeof(display->title)-2);
		display->title[sizeof(display->title)-1] = 0;
		counter++;
		if ( display->java_bitmap != 0 )
		{
			//for (i=0; i<IGUANA_HEIGHT*IGUANA_WIDTH; i++)
			//	BI.bitmap[i] = (BI.bitmap[i] != 0) ? BI.bitmap[i] : Display_bitmaps[Display_contractnum][i];
			memcpy(display->java_bitmap,BI.bitmap,IGUANA_HEIGHT*IGUANA_WIDTH*sizeof(int));
			while ( mmbitmap_updated(display->vp) == 0 )
				usleep(100);
			mmbitmap_update(display->vp);
			//release_lockid(DISPLAY_LOCKID);
#ifndef JDATA_MODE
			int32_t display_idle(register int32_t microsleep);
			display_idle(display->microsleep);
#endif
			mmbitmap_set_title(display->vp,display->title);
			//if ( display->microsleep != 0 )
			//	usleep(display->microsleep);
		}
		/*if ( Display_pause != 0 )
		 Parsed_weekinds[Display_contractnum] += Display_clumpsize;//MAX(60,Display_clumpsize)+(0*(IGUANA_WIDTH/2) * Display_clumpsize);
		 if ( Parsed_weekinds[Display_contractnum] > NUM_WEEKINDS-60 )
		 {
		 Display_pause = 1;
		 Parsed_weekinds[Display_contractnum] = NUM_WEEKINDS-60;
		 }*/
		if ( 0 )
		{
			if ( Parsed_weekinds[Display_contractnum] < Parsedbits[Display_contractnum].weekind )
				Parsed_weekinds[Display_contractnum] = Parsedbits[Display_contractnum].weekind;//jdatetime_to_wbits(actual_gmt_jdatetime()).weekind;
		}
		else
		{
			jdatetime = actual_gmt_jdatetime();
			Parsed_weekinds[Display_contractnum] = jdatetime_to_wbits(jdatetime).weekind + 0*(dst_adjust(jdatetime)/FASTEST_RESOLUTION);
		}
		for (c=0; c<NUM_COMBINED; c++)
			Parsed_weekinds[c] = Parsed_weekinds[Display_contractnum];
	}
	return(0);
}
#endif

void iguana_bitmapbundle(struct iguana_info *coin,uint8_t *rect,int32_t rowwidth,int32_t width,int32_t height,struct iguana_bundle *bp)
{
    int32_t x,y; uint8_t red,green,blue,*ptr; struct iguana_block *block; double frac,sum = 0.;
    if ( bp != 0 )
    {
        if ( bp->red == 0 )
            bp->red = rand(), bp->green = rand(), bp->blue = rand();
        red = green = blue = 0;
        frac = (double)bp->n / (width * height);
        for (y=0; y<height; y++,rect+=rowwidth*3)
        {
            ptr = rect;
            for (x=0; x<width; x++,sum+=frac)
            {
                green = red = blue = 0;
                if ( bp->ramchain.H.data != 0 )
                {
                    blue = 0xff;
                    if ( bp->bundleheight+(int32_t)sum > coin->blocks.hwmchain.height )
                        red = 0xff, green = 0xff, blue = 0;
                    else green = 0xff, blue = 0, red = 0;
                }
                else
                {
                    red = green = blue = 0;
                    if ( (block= bp->blocks[(int32_t)sum]) != 0 )
                    {
                        blue = 0xff;
                        if ( block->RO.recvlen != 0 )
                            green = 0xcc;
                        else green = 0x40;
                        if ( block->fpipbits != 0 )
                            red = 0xcc;
                        else red = 0x40;
                    }
                }
                *ptr++ = red, *ptr++ = green, *ptr++ = blue;
            }
        }
    }
}

struct iguana_bitmap *iguana_bitmapfind(char *name)
{
    struct iguana_info *coin; int32_t width=1,height=1,n,hdrsi,x,y;
    if ( ((coin= iguana_coinfind(name)) != 0 || (coin= iguana_coinfind("BTCD")) != 0) && coin->screen != 0 )
    {
        strcpy(coin->screen->name,coin->symbol);
        coin->screen->amplitude = 255;
        coin->screen->width = IGUANA_WIDTH;
        coin->screen->height = IGUANA_HEIGHT;
        memset(coin->screen->data,0xff,sizeof(coin->screen->data));
        if ( coin->bundlescount > 0 )
        {
            n = 100;
            while ( n > 0 )
            {
                width = IGUANA_WIDTH / n;
                height = IGUANA_HEIGHT / n;
                //printf("n.%d -> (%d %d) rects.%d vs %d\n",n,width,height,width*height,coin->bundlescount);
                if ( width*height >= coin->bundlescount )
                    break;
                n--;
            }
            for (y=hdrsi=0; y<height; y++)
            {
                for (x=0; x<width; x++,hdrsi++)
                {
                    if ( hdrsi >= coin->bundlescount )
                        break;
                    iguana_bitmapbundle(coin,&coin->screen->data[3*(y*coin->screen->width*n + x*n)],coin->screen->width,n,n,coin->bundles[hdrsi]);
                }
            }
        }
        return(coin->screen);
    }
    return(0);
}

void iguana_bitmap(char *space,int32_t max,char *name)
{
    struct iguana_info *coin; struct iguana_bitmap *rect; char pixel[64],fname[512];
    uint8_t *ptr; int32_t h,w,red,green,blue,x,y,n,len = 0;
    if ( name == 0 || name[0] == 0 )
        name = "BTCD";
    coin = iguana_coinfind(name);
    if ( (rect= iguana_bitmapfind(name)) == 0 )
    {
        strcpy(space,"{\"name\":\"nobitmap\",\"amplitude\":222,\"width\":1,\"height\":1,\"pixels\":[222,0,22]}");
        //sprintf(space,"Content-type: text/standard\r\n");
        //sprintf(space+strlen(space),"Content-Length: %ld\r\n\r\n",strlen(buf));
        //strcpy(space,buf);
        printf("bitmap.[%s]\n",space);
    }
    else
    {
        ptr = rect->data;
        h = rect->height, w = rect->width;
        for (y=0; y<h; y++)
        {
            for (x=0; x<w; x++)
            {
                red = *ptr++, green = *ptr++, blue = *ptr++;
                sprintf(pixel,"%u,%u,%u,",red,green,blue);
                n = (int32_t)strlen(pixel);
                memcpy(&space[len],pixel,n);
                len += n;
            }
        }
        space[len-1] = ']', space[len++] = '}', space[len++] = 0;
        if ( cJSON_Parse(space) == 0 )
            printf("ERROR PARSING BITMAP\n");
        //if ( (rand() % 100) == 0 )
        {
            sprintf(fname,"%s.jpg",name);
            gen_jpegfile(fname,1,rect->data,rect->width,rect->height);
        }
        //printf("BIGMAP.(%s)\n",space);
    }
}

