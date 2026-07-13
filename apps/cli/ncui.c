#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <ncurses.h>
#include <panel.h>
#include <form.h>
#include <sys/ioctl.h>

#include "basic_defs.h"
#include "util.h"
#include "circlist.h"
#include "config.h"
#include "ncui.h"
#include "poll.h"
#include "base58.h"
#include "bitc.h"
#include "bitc_ui.h"
#include "bitc-defs.h"
#include "ip_info.h"

#define LGPFX   "NCUI:"

static const int pageDelta = 20;

#define PAIR_BLACK      COLOR_PAIR(0)
#define PAIR_RED        COLOR_PAIR(1)
#define PAIR_GREEN      COLOR_PAIR(2)
#define PAIR_YELLOW     COLOR_PAIR(3)
#define PAIR_BLUE       COLOR_PAIR(4)
#define PAIR_MAGENTA    COLOR_PAIR(5)
#define PAIR_CYAN       COLOR_PAIR(6)
#define PAIR_WHITE      COLOR_PAIR(7)

enum NCColorPair {
   NC_CPAIR_BASE03 = 16,
   NC_CPAIR_BASE02,
   NC_CPAIR_BASE01,
   NC_CPAIR_BASE00,
   NC_CPAIR_BASE0,
   NC_CPAIR_BASE1,
   NC_CPAIR_BASE2,
   NC_CPAIR_BASE3,
   NC_CPAIR_YELLOW,
   NC_CPAIR_ORANGE,
   NC_CPAIR_RED,
   NC_CPAIR_MAGENTA,
   NC_CPAIR_VIOLET,
   NC_CPAIR_BLUE,
   NC_CPAIR_CYAN,
   NC_CPAIR_GREEN,
};


enum NCColor {
   NC_COL_BASE03 = 128,
   NC_COL_BASE02,
   NC_COL_BASE01,
   NC_COL_BASE00,
   NC_COL_BASE0,
   NC_COL_BASE1,
   NC_COL_BASE2,
   NC_COL_BASE3,
   NC_COL_YELLOW,
   NC_COL_ORANGE,
   NC_COL_RED,
   NC_COL_MAGENTA,
   NC_COL_VIOLET,
   NC_COL_BLUE,
   NC_COL_CYAN,
   NC_COL_GREEN,
};


enum NCUIFormField {
   TX_FIELD_ADDR_LABEL          = 0,
   TX_FIELD_ADDR                = 1,
   TX_FIELD_LABEL_LABEL         = 2,
   TX_FIELD_LABEL               = 3,
   TX_FIELD_AVAILABLE_LABEL     = 4,
   TX_FIELD_AVAILABLE           = 5,
   TX_FIELD_AVAILABLE_BTC_LABEL = 6,
   TX_FIELD_AMOUNT_LABEL        = 7,
   TX_FIELD_AMOUNT              = 8,
   TX_FIELD_AMOUNT_BTC_LABEL    = 9,
   TX_FIELD_CANCEL              = 10,
   TX_FIELD_OK                  = 11,
   TX_FIELD_LAST                = 12,
   TX_FIELD_NUM                 = 13,
};

/*
 * Local types.
 */
#define GET_PANEL(li_) \
      CIRCLIST_CONTAINER(li, struct ncpanel, item)

struct ncpanel;
struct ncui;

typedef void (ncui_panel_destroy_cb)(void *clientData);


enum PanelType {
   PANEL_DASHBOARD,
   PANEL_WALLET,
   PANEL_TX,
   PANEL_BLOCKLIST,
   PANEL_FX,
   PANEL_LOG,
   PANEL_PEERS,
   PANEL_CONTACTS,
};


struct ncpanel {
   enum PanelType          type;
   char                   *label;
   PANEL                  *panel;
   WINDOW                 *window;
   void                   *clientData;
   ncui_panel_destroy_cb  *destroy_cb;
   int                     num_lines;
   int                     max_lines;
   bool                    scroll_on;
   int                     scroll_y;
   bool                    select_on;
   int                     select_y;
   struct circlist_item    item;
};


static const struct {
   enum PanelType type;
} allPanels[] = {
   { PANEL_DASHBOARD },
   { PANEL_WALLET    },
   { PANEL_CONTACTS  },
   { PANEL_TX        },
   { PANEL_FX        },
   { PANEL_BLOCKLIST },
   { PANEL_PEERS     },
   { PANEL_LOG       },
};

struct ncui {
   struct circlist_item *panelList;
   struct ncpanel       *panelTop;
   char                  timeStr[64];
   char                  kbdInput[128];
   size_t                kbdInputLen;

   PANEL                *fpanel;
   FORM                 *form;
   FIELD                *field[TX_FIELD_NUM];
   WINDOW               *fwin;
   bool                  curs_on;
   int                   fwin_width;
   int                   fwin_height;
};


/*
 * Local functions.
 */
typedef struct ncpanel* (panel_create_cb)(void);

static struct ncpanel* ncui_create_peers(void);
static struct ncpanel* ncui_create_blocklist(void);
static struct ncpanel* ncui_create_dashboard(void);
static struct ncpanel* ncui_create_wallet(void);
static struct ncpanel* ncui_create_log(void);
static struct ncpanel* ncui_create_tx(void);
static struct ncpanel* ncui_create_fx(void);
static struct ncpanel* ncui_create_contacts(void);

static void ncui_redraw(void);
static void ncui_panel_switch_to(struct ncpanel *panel);
static void ncui_blocklist_update(void);
static void ncui_dashboard_update(void);
static void ncui_tx_form_create(struct ncui *ncui);
static void ncui_input_kbd_cb(struct ncui *ncui,
                              const char *cmd);

static const struct {
   enum PanelType    type;
   panel_create_cb  *panelCreate;
} panelDescriptors[] = {
   { PANEL_DASHBOARD, ncui_create_dashboard },
   { PANEL_BLOCKLIST, ncui_create_blocklist },
   { PANEL_WALLET,    ncui_create_wallet },
   { PANEL_TX,        ncui_create_tx },
   { PANEL_CONTACTS,  ncui_create_contacts },
   { PANEL_FX,        ncui_create_fx },
   { PANEL_LOG,       ncui_create_log },
   { PANEL_PEERS,     ncui_create_peers },
};


/*
 *---------------------------------------------------------------------
 *
 * ncui_get_max_tx_amount --
 *
 *      The maximum amount one can send is the sum of all our confirmed coins
 *      minus all the transactions we've initiated that are pending.
 *
 *---------------------------------------------------------------------
 */

static uint64
ncui_get_max_tx_amount(void)
{
   struct bitcui_tx *tx_info = btcui->tx_info;
   int64 pendingDebit = 0;
   int64 conf = 0;
   int i;

   for (i = 0; i < btcui->tx_num; i++) {
      int64 txValue = tx_info[i].value;

      if (tx_info[i].blockHeight != -1) {
         conf += txValue;
      } else if (txValue < 0) {
         ASSERT(tx_info[i].blockHeight == -1);

         pendingDebit += txValue;
      }
   }
   ASSERT(pendingDebit <= 0);
   return conf + pendingDebit;
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_get_balance --
 *
 *---------------------------------------------------------------------
 */

static void
ncui_get_balance(int64 *confirmed,
                 int64 *unConfirmed,
                 int *numTxUnconf)
{
   struct bitcui_tx *tx_info = btcui->tx_info;
   int64 conf = 0;
   int64 pending = 0;
   int numUnconf = 0;
   int i;

   for (i = 0; i < btcui->tx_num; i++) {
      /*
       * tx that have less than 6 confirmations are deemed unconfirmed.
       */
      if ((btcui->height - tx_info[i].blockHeight + 1) >= 6) { // ~ 1h
         conf += tx_info[i].value;
      } else {
         pending += tx_info[i].value;
         numUnconf++;
      }
   }
   *confirmed = conf;
   *unConfirmed = conf + pending;
   *numTxUnconf = numUnconf;
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_doupdate --
 *
 *---------------------------------------------------------------------
 */

static void
ncui_doupdate(void)
{
   struct ncui *ncui = btc->ui;

   if (ncui->form) {
      int sy = (LINES - ncui->fwin_width) * 4 / 10;
      int sx = (COLS  - ncui->fwin_height) / 2;
      int ey = (LINES - ncui->fwin_width) * 4 / 10  + ncui->fwin_width;
      int ex = (COLS  - ncui->fwin_height) / 2      + ncui->fwin_height;

      pnoutrefresh(ncui->fwin, 0, 0, sy, sx, ey, ex);
   }
   doupdate();
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_draw_frame --
 *
 *---------------------------------------------------------------------
 */

static void
ncui_draw_frame(void)
{
   WINDOW *win = stdscr;

   ASSERT(mutex_islocked(btcui->lock));

   //wclear(win);
   werase(win);
   wmove(win, 1, 0);
   box(win, 0, 0);
   mvwaddch(win, 2, 0, ACS_LTEE);
   mvwhline(win, 2, 1, ACS_HLINE, COLS - 2);
   mvwaddch(win, 2, COLS - 1, ACS_RTEE);

   wnoutrefresh(win);
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_panel_refresh --
 *
 *---------------------------------------------------------------------
 */

static void
ncui_panel_refresh(const struct ncpanel *panel)
{
   ASSERT(mutex_islocked(btcui->lock));

   pnoutrefresh(panel->window, panel->scroll_y, 0, 3, 1, LINES - 3, COLS - 2);
   ncui_doupdate();
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_panel_check_refresh --
 *
 *      This function is called from log_info(), so it should not call log_info() itself.
 *
 *---------------------------------------------------------------------
 */

static void
ncui_panel_check_refresh(const struct ncpanel *panel)
{
   struct ncui *ncui = btc->ui;
   if (ncui->panelTop == panel) {
      ncui_panel_refresh(panel);
   }
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_get_panel_by_type --
 *
 *---------------------------------------------------------------------
 */

static struct ncpanel *
ncui_get_panel_by_type(enum PanelType idx)
{
   struct circlist_item *li;

   CIRCLIST_SCAN(li, btc->ui->panelList) {
      struct ncpanel *panel = GET_PANEL(li);
      if (idx == panel->type) {
         return panel;
      }
   }
   return NULL;
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_panel_prev --
 *
 *---------------------------------------------------------------------
 */

static struct ncpanel *
ncui_panel_prev(void)
{
   struct circlist_item *li = btc->ui->panelTop->item.prev;
   return GET_PANEL(li);
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_panel_next --
 *
 *---------------------------------------------------------------------
 */

static struct ncpanel *
ncui_panel_next(void)
{
   struct circlist_item *li = btc->ui->panelTop->item.next;
   return GET_PANEL(li);
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_get_term_size --
 *
 *---------------------------------------------------------------------
 */

static void
ncui_get_term_size(int *y, int *x)
{
   struct winsize ws;

   *y = LINES;
   *x = COLS;
   if (ioctl(0, TIOCGWINSZ, &ws) != 0) {
      log_info(LGPFX" failed to get terminal size: %s\n", strerror(errno));
   } else {
      *y = ws.ws_row;
      *x = ws.ws_col;
   }
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_signal_cb --
 *
 *---------------------------------------------------------------------
 */

static void
ncui_signal_cb(int sig)
{
   int x, y;

   ASSERT(sig == SIGWINCH);

   /*
    * Since we call some heavyweight functions from the signal handler, it's
    * possible (and in fact very common) to receive a signal while we're in the
    * middle of processing one.
    */
   struct sigaction sa = { .sa_handler = SIG_IGN };

   sigemptyset(&sa.sa_mask);
   sigaction(SIGWINCH, &sa, NULL);

   ncui_get_term_size(&y, &x);
   resizeterm(y, x);
   ncui_redraw();

   sa = (struct sigaction){ .sa_handler = ncui_signal_cb };
   sigemptyset(&sa.sa_mask);
   sigaction(SIGWINCH, &sa, NULL);
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_status_update --
 *
 *---------------------------------------------------------------------
 */

void
ncui_status_update(bool update)
{
   struct ncui *ncui = btc->ui;
   WINDOW *win = stdscr;
   const char *type;

   ASSERT(mutex_islocked(btcui->lock));

   mutex_lock(btcui->lock);

   wmove(win, LINES - 2, 2);
   wclrtoeol(win);

   if (time(NULL) >= btcui->statusExpiry) {
      free(btcui->statusStr);
      btcui->statusStr = NULL;
      btcui->statusExpiry = 0;
   }

   if (btcui->statusStr) {
      wattron(win, PAIR_CYAN);
      wprintw(win, "%s", btcui->statusStr);
      wattroff(win, PAIR_CYAN);
   }

   type = btc->testnet ? "[TESTNET]" : NULL;

   const char *proxyStr = NULL;
   if (btc->socks5_proxy) {
      proxyStr = "[SOCKS5]";
   }

   const char *wltStr = NULL;
   int attr;
   switch (btc->wallet_state) {
   case WALLET_PLAIN:
      attr = PAIR_RED;
      wltStr = "[unencrypted]";
      break;
   case WALLET_ENCRYPTED_LOCKED:
      attr = PAIR_GREEN;
      wltStr = "[locked]";
      break;
   case WALLET_ENCRYPTED_UNLOCKED:
      attr = PAIR_RED;
      wltStr = "[unlocked]";
      break;
   default:
      break;
   }

   if (type) {
      size_t wlen = wltStr ? strlen(wltStr) : 0;
      wattron(win, PAIR_MAGENTA);
      mvwprintw(win, LINES - 2, COLS - strlen(ncui->timeStr) - 3
                - wlen - (proxyStr ? strlen(proxyStr) : 0) - strlen(type),
                "%s", type);
      wattroff(win, PAIR_MAGENTA);
   }

   if (proxyStr) {
      size_t wlen = wltStr ? strlen(wltStr) : 0;
      wattron(win, PAIR_GREEN);
      mvwprintw(win, LINES - 2, COLS - strlen(ncui->timeStr) - 3 - wlen - strlen(proxyStr),
                "%s", proxyStr);
      wattroff(win, PAIR_GREEN);
   }

   if (wltStr) {
      wattron(win, attr);
      mvwprintw(win, LINES - 2, COLS - strlen(ncui->timeStr) - 3 - strlen(wltStr),
                "%s", wltStr);
      wattroff(win, attr);
   }

   ASSERT(ncui->timeStr);

   wattron(win, PAIR_BLACK);
   mvwprintw(win, LINES - 2, COLS - strlen(ncui->timeStr) - 2,
             "%s", ncui->timeStr);
   wattroff(win, PAIR_BLACK);

   mvwaddch(win, LINES - 2, COLS - 1, ACS_VLINE);

   wnoutrefresh(win);
   if (update) {
      ncui_doupdate();
   }
   mutex_unlock(btcui->lock);
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_update_time_str --
 *
 *---------------------------------------------------------------------
 */

static void
ncui_update_time_str(void)
{
   struct tm tm_buf;
   time_t t;

   t = time(NULL);
   localtime_r(&t, &tm_buf);
   strftime(btc->ui->timeStr, sizeof btc->ui->timeStr, "%T", &tm_buf);
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_time_cb --
 *
 *---------------------------------------------------------------------
 */

void
ncui_time_cb(void *clientData)
{
   mutex_lock(btcui->lock);

   ncui_update_time_str();
   ncui_status_update(1);

   mutex_unlock(btcui->lock);
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_contacts_update --
 *
 *---------------------------------------------------------------------
 */

static void
ncui_contacts_update(void)
{
   struct ncpanel *panel = ncui_get_panel_by_type(PANEL_CONTACTS);
   WINDOW *win = panel->window;
   int i;
   int n;

   werase(win);

   n = config_getint64(btc->contactsCfg, 0, "contacts.numEntries");

   for (i = 0; i < n; i++) {
      char *addr  = config_getstring(btc->contactsCfg, NULL, "contact%u.addr", i);
      char *label = config_getstring(btc->contactsCfg, NULL, "contact%u.label", i);

      if (addr == NULL || label == NULL) {

         continue;
      }

      wattron(win, PAIR_GREEN);
      mvwprintw(win, i, 1, "%3u",  i);
      wattroff(win, PAIR_GREEN);
      mvwaddch(win,  i, 5, ACS_VLINE);
      mvwprintw(win, i, 7, "%s", addr);
      mvwaddch(win,  i, 42, ACS_VLINE);
      mvwprintw(win, i, 44, "%s", label);

      free(addr);
      free(label);
   }
   panel->num_lines = n;

   ncui_panel_check_refresh(panel);
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_info_update --
 *
 *---------------------------------------------------------------------
 */

void
ncui_info_update(void)
{
   ASSERT(mutex_islocked(btcui->lock));

   ncui_blocklist_update();
   ncui_dashboard_update();
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_label_top_panel --
 *
 *---------------------------------------------------------------------
 */

static void
ncui_label_top_panel(void)
{
   struct circlist_item *li;
   WINDOW *win = stdscr;
   int off;

   ASSERT(mutex_islocked(btcui->lock));

   off = 3;
   CIRCLIST_SCAN(li, btc->ui->panelList) {
      struct ncpanel *panel = GET_PANEL(li);
      bool hl = panel == btc->ui->panelTop;

      wmove(win, 1, off);
      wclrtoeol(win);
      wattron(win, PAIR_CYAN);
      if (hl) {
         wattron(win, A_REVERSE);
      }
      mvwprintw(win, 1, off, "%s", panel->label);
      off += strlen(panel->label) + 1;
      if (hl) {
         wattroff(win, A_REVERSE);
      }
      off += 2;
      wattroff(win, PAIR_CYAN);
      mvwaddch(win, 1, 0, ACS_VLINE);
      mvwaddch(win, 1, COLS - 1, ACS_VLINE);
   }
   wnoutrefresh(win);
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_panel_switch_to --
 *
 *---------------------------------------------------------------------
 */

static void
ncui_panel_switch_to(struct ncpanel *panel)
{
   if (panel == NULL) {
      return;
   }
   btc->ui->panelTop = panel;
   top_panel(panel->panel);
   update_panels();

   ncui_label_top_panel();
   ncui_panel_refresh(panel);
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_panel_scroll --
 *
 *---------------------------------------------------------------------
 */

static void
ncui_panel_scroll(struct ncpanel *panel,
                  bool down,
                  int delta)
{
   int height;

   if (panel->scroll_on == 0) {
      return;
   }
   log_info(LGPFX" scroll=%d select=%d numLines=%d/%d select_y=%d scroll_y=%d delta=%d down=%u\n",
       panel->scroll_on, panel->select_on,
       panel->num_lines, panel->max_lines,
       panel->select_y, panel->scroll_y, delta, down);

   height = LINES - 5;
   if (panel->select_on) {
      if (down) {
         panel->select_y += delta;
         if (panel->select_y > panel->scroll_y + height) {
            panel->scroll_y = panel->select_y - height;
         }
      } else {
      }

   } else {
      if (down) {
         panel->scroll_y += delta;
         panel->scroll_y = MIN(panel->scroll_y, panel->num_lines - (height - 1));
      } else {
         panel->scroll_y -= MIN(panel->scroll_y, delta);
      }
   }
   ncui_panel_check_refresh(panel);
}


/*
 *--------------------------------------------------------------------------
 *
 * ncui_tx_form_destroy --
 *
 *--------------------------------------------------------------------------
 */

static void
ncui_tx_form_destroy(struct ncui *ncui)
{
   int i;

   ASSERT(ncui->form);
   unpost_form(ncui->form);
   free_form(ncui->form);
   delwin(ncui->fwin);
   del_panel(ncui->fpanel);
   update_panels();
   ncui->curs_on = 0;
   curs_set(0);
   ncui->form = NULL;
   ncui->fwin = NULL;
   ncui->fpanel = NULL;

   for (i = 0; i < ARRAYSIZE(ncui->field); i++) {
      free_field(ncui->field[i]);
   }
   ncui_draw_frame();
   ncui_label_top_panel();
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_tx_form_process --
 *
 *---------------------------------------------------------------------
 */

static void
ncui_tx_form_process(struct ncui *ncui)
{
   struct btc_tx_desc *desc;
   const char *label;
   const char *value;
   const char *addr;

   addr  = field_buffer(ncui->field[TX_FIELD_ADDR], 0);
   label = field_buffer(ncui->field[TX_FIELD_LABEL], 0);
   value = field_buffer(ncui->field[TX_FIELD_AMOUNT], 0);

   log_info(LGPFX" tX: addr=%s lbl='%s' val=%s BTC\n",
       addr, label, value);

   if (!b58_pubkey_is_valid(addr)) {
      bitcui_set_status("address %s is invalid", addr);
      return;
   }

   desc = safe_calloc(1, sizeof *desc);

   strncpy(desc->label, label, sizeof desc->label);
   strncpy(desc->dst[0].addr, addr, sizeof desc->dst[0].addr);

   str_trim(desc->label, sizeof desc->label);

   desc->dst[0].value = atof(value) * ONE_BTC;
   desc->num_addr     = 1;
   desc->fee          = -1; /* means default */
   desc->total_value  = atof(value) * ONE_BTC;

   bitcui_set_status("TX: %.8f BTC to %s", desc->total_value / ONE_BTC, addr);

   bitc_req_tx(desc);
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_tx_form_complete --
 *
 *---------------------------------------------------------------------
 */

static void
ncui_tx_form_complete(struct ncui *ncui,
                      bool ok)
{
   if (ok) {
      ncui_tx_form_process(ncui);
   } else {
      bitcui_set_status("TX cancelled.");
   }

   ncui_tx_form_destroy(ncui);
   ncui_panel_refresh(ncui->panelTop);
}


/*
 *--------------------------------------------------------------------------
 *
 * ncui_form_input_cb --
 *
 *--------------------------------------------------------------------------
 */

static void
ncui_form_input_cb(struct ncui *ncui)
{
   bool isCancel;
   bool isOK;
   FIELD *f;
   int c;

   ASSERT(ncui->form);

   f = current_field(ncui->form);

   isOK     = f == ncui->field[TX_FIELD_OK];
   isCancel = f == ncui->field[TX_FIELD_CANCEL];

   c = wgetch(ncui->fwin);

   bitcui_set_status("key=%u pressed", c);

   switch (c) {
   case '`':
      isOK = 0;
      isCancel = 1;
   case '\r':
      if (isOK || isCancel) {
         ncui_tx_form_complete(ncui, isOK);
      } else {
         form_driver(ncui->form, REQ_NEXT_FIELD);
         form_driver(ncui->form, REQ_END_LINE);
      }
      break;
   case 9: /* TAB */
   case KEY_DOWN:
      form_driver(ncui->form, REQ_NEXT_FIELD);
      form_driver(ncui->form, REQ_END_LINE);
      break;
   case KEY_UP:
   case KEY_BTAB:
      form_driver(ncui->form, REQ_PREV_FIELD);
      form_driver(ncui->form, REQ_END_LINE);
      break;
   case KEY_LEFT:
      if (isOK || isCancel){
         form_driver(ncui->form, REQ_PREV_FIELD);
         form_driver(ncui->form, REQ_END_LINE);
      } else {
         form_driver(ncui->form, REQ_LEFT_CHAR);
      }
      break;
   case KEY_RIGHT:
      if (isOK || isCancel){
         form_driver(ncui->form, REQ_NEXT_FIELD);
         form_driver(ncui->form, REQ_END_LINE);
      } else {
         form_driver(ncui->form, REQ_RIGHT_CHAR);
      }
      break;
   case 127:
   case KEY_BACKSPACE:   form_driver(ncui->form, REQ_DEL_PREV); break;
   case KEY_DC:          form_driver(ncui->form, REQ_DEL_CHAR); break;
   case KEY_HOME:        form_driver(ncui->form, REQ_BEG_FIELD); break;
   case KEY_END:         form_driver(ncui->form, REQ_END_FIELD); break;
   default:
                         form_driver(ncui->form, c);
                         break;
   }
   if (ncui->form) {
      f = current_field(ncui->form);
      isOK     = f == ncui->field[TX_FIELD_OK];
      isCancel = f == ncui->field[TX_FIELD_CANCEL];
      if (isOK || isCancel) {
         if (ncui->curs_on) {
            curs_set(0);
            ncui->curs_on = 0;
         }
         set_field_fore(ncui->field[TX_FIELD_CANCEL], isCancel ? A_REVERSE : A_NORMAL);
         set_field_fore(ncui->field[TX_FIELD_OK],     isOK     ? A_REVERSE : A_NORMAL);
      } else {
         if (ncui->curs_on == 0) {
            curs_set(1);
            ncui->curs_on = 1;
         }
         set_field_fore(ncui->field[TX_FIELD_CANCEL], A_NORMAL);
         set_field_fore(ncui->field[TX_FIELD_OK], A_NORMAL);
      }
   }
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_normal_input_cb --
 *
 *---------------------------------------------------------------------
 */

static void
ncui_normal_input_cb(struct ncui *ncui)
{
   struct ncpanel *panel;
   int c;

   ASSERT(!ncui->form);

   c = getch();

   switch (c) {
   case '\r':
      if (ncui->kbdInputLen > 0) {
         ncui->kbdInput[ncui->kbdInputLen] = '\0';

         ncui_input_kbd_cb(ncui, ncui->kbdInput);

         memset(ncui->kbdInput, 0, sizeof(ncui->kbdInput));
         ncui->kbdInputLen = 0;
      }
      break;
   case 127: // backspace on mac
   case KEY_BACKSPACE:
   case KEY_DC:
      if (ncui->kbdInputLen >= 1) {
         ncui->kbdInputLen--;
         ncui->kbdInput[ncui->kbdInputLen] = '\0';
      }
      bitcui_set_status("%s", ncui->kbdInput);
      break;
   case '!':
   case '-':
   case '*':
   case '/':
   case '(':
   case ')':
   case '{':
   case '}':
   case '[':
   case ']':
   case ' ':
   case '.':
   case ':':
      ncui->kbdInput[ncui->kbdInputLen++] = c;
      bitcui_set_status("%s", ncui->kbdInput);
      break;
   case KEY_IC:
      bitcui_set_status("Insert pressed.");
      break;
   case KEY_END:
      ncui_panel_scroll(ncui->panelTop, 1,
                        ncui->panelTop->max_lines - ncui->panelTop->scroll_y);
      bitcui_set_status("bottom");
      break;
   case KEY_HOME:
      ncui_panel_scroll(ncui->panelTop, 0, ncui->panelTop->scroll_y);
      bitcui_set_status("top");
      break;
   case KEY_NPAGE:
   case KEY_PPAGE:
      ncui_panel_scroll(ncui->panelTop, c == KEY_NPAGE, pageDelta);
      if (ncui->panelTop->num_lines != 0) {
         bitcui_set_status("scroll: %u%%", 100 * ncui->panelTop->scroll_y
                          / ncui->panelTop->num_lines);
      }
      break;
   case KEY_DOWN:
   case KEY_UP:
      ncui_panel_scroll(ncui->panelTop, c == KEY_DOWN, 1);
      break;
   case KEY_RIGHT:
   case KEY_LEFT:
      if (c == KEY_RIGHT) {
         panel = ncui_panel_next();
      } else {
         panel = ncui_panel_prev();
      }
      ncui_panel_switch_to(panel);
      break;
   case KEY_F(1):
      bitcui_set_status("f1");
      goto here;
   case KEY_F(2):
      bitcui_set_status("f2");
      goto here;
   case KEY_F(3):
      bitcui_set_status("f3");
      goto here;
   case KEY_F(4):
      bitcui_set_status("f4");
here:
      panel = ncui_get_panel_by_type(allPanels[c - KEY_F(1)].type);
      ncui_panel_switch_to(panel);
      break;
   case '`':
   case 'q':
      bitcui_set_status("exit requested.");
      bitc_req_stop();
      break;
   case KEY_RESIZE:
      ncui_redraw();
      break;
   case 20: // CTRL-T
      if (!bitc_state_ready()) {
         bitcui_set_status("failed to initiate tx: still sync'ing..");
         break;
      }
      if (btc->wallet_state == WALLET_ENCRYPTED_LOCKED) {
         bitcui_set_status("failed to initiate tx: wallet is encrypted.");
         break;
      }
      ncui_tx_form_create(ncui);
      break;
   default:
      bitcui_set_status("char: %d", c);
      break;
   }
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_input_cb --
 *
 *---------------------------------------------------------------------
 */

void
ncui_input_cb(void *clientData)
{
   struct ncui *ncui = btc->ui;

   mutex_lock(btcui->lock);

   if (ncui->form) {
      ncui_form_input_cb(ncui);
   } else {
      ncui_normal_input_cb(ncui);
   }

   ncui_panel_refresh(ncui->panelTop);

   mutex_unlock(btcui->lock);
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_destroy_panel --
 *
 *---------------------------------------------------------------------
 */

static void
ncui_destroy_panel(struct ncpanel *panel)
{
   if (panel->destroy_cb) {
      panel->destroy_cb(panel->clientData);
   }
   del_panel(panel->panel);
   delwin(panel->window);

   free(panel->clientData);
   free(panel->label);
   free(panel);
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_create_panel --
 *
 *---------------------------------------------------------------------
 */

static struct ncpanel *
ncui_create_panel(int maxLines,
                  size_t sz)
{
   struct ncpanel *panel;

   panel = safe_calloc(1, sizeof *panel);
   panel->scroll_y   = 0;
   panel->scroll_on  = 1;
   panel->label      = NULL;
   panel->clientData = NULL;
   panel->destroy_cb = NULL;
   panel->num_lines  = 0;
   panel->max_lines  = MAX(LINES + 50, maxLines);
   panel->window = newpad(panel->max_lines, 250);
   panel->panel = new_panel(panel->window);
   set_panel_userptr(panel->panel, panel);

   if (sz > 0) {
      panel->clientData = safe_calloc(1, sz);
   }

   circlist_init_item(&panel->item);
   circlist_queue_item(&btc->ui->panelList, &panel->item);

   return panel;
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_redraw --
 *
 *---------------------------------------------------------------------
 */

static void
ncui_redraw(void)
{
   struct ncui *ncui = btc->ui;

   mutex_lock(btcui->lock);

   ncui_draw_frame();
   ncui_label_top_panel();
   ncui_status_update(0);

   ncui_panel_refresh(ncui->panelTop);
   ncui_doupdate();

   mutex_unlock(btcui->lock);
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_ncurses_init --
 *
 *---------------------------------------------------------------------
 */

static int
ncui_ncurses_init(void)
{
   int y, x;

   log_info(LGPFX" using ncurses %s\n", curses_version());
   ncui_get_term_size(&y, &x);
   log_info(LGPFX" starting terminal dimension: %d x %d\n", y, x);

   initscr();
   savetty();
   keypad(stdscr, TRUE);
   nodelay(stdscr, TRUE);
   nonl();
   intrflush(stdscr, FALSE);
   noecho();
   cbreak();
   clear();
   curs_set(0);

// SOLARIZED HEX     16/8 TERMCOL  XTERM/HEX   L*A*B      RGB         HSB
// --------- ------- ---- -------  ----------- ---------- ----------- -----------
// base03    #002b36  8/4 brblack  234 #1c1c1c 15 -12 -12   0  43  54 193 100  21
// base02    #073642  0/4 black    235 #262626 20 -12 -12   7  54  66 192  90  26
// base01    #586e75 10/7 brgreen  240 #585858 45 -07 -07  88 110 117 194  25  46
// base00    #657b83 11/7 bryellow 241 #626262 50 -07 -07 101 123 131 195  23  51
// base0     #839496 12/6 brblue   244 #808080 60 -06 -03 131 148 150 186  13  59
// base1     #93a1a1 14/4 brcyan   245 #8a8a8a 65 -05 -02 147 161 161 180   9  63
// base2     #eee8d5  7/7 white    254 #e4e4e4 92 -00  10 238 232 213  44  11  93
// base3     #fdf6e3 15/7 brwhite  230 #ffffd7 97  00  10 253 246 227  44  10  99
// yellow    #b58900  3/3 yellow   136 #af8700 60  10  65 181 137   0  45 100  71
// orange    #cb4b16  9/3 brred    166 #d75f00 50  50  55 203  75  22  18  89  80
// red       #dc322f  1/1 red      160 #d70000 50  65  45 220  50  47   1  79  86
// magenta   #d33682  5/5 magenta  125 #af005f 50  65 -05 211  54 130 331  74  83
// violet    #6c71c4 13/5 brmagenta 61 #5f5faf 50  15 -45 108 113 196 237  45  77
// blue      #268bd2  4/4 blue      33 #0087ff 55 -10 -45  38 139 210 205  82  82
// cyan      #2aa198  6/6 cyan      37 #00afaf 60 -35 -05  42 161 152 175  74  63
// green     #859900  2/2 green     64 #5f8700 60 -20  65 133 153   0  68 100  60

   if (!has_colors()) {
      return 1;
   }
   start_color();
   use_default_colors();

   log_info(LGPFX" has_color() = %d -- can_change_color() = %d\n",
       has_colors(), can_change_color());
   log_info(LGPFX" COLORS = %d -- COLORPAIRS = %d\n", COLORS, COLOR_PAIRS);

   if (0 && can_change_color()) {
#define ADJ(_x) (((_x) * 1000) / 256)
      init_color(NC_COL_BASE03   , ADJ(  0), ADJ( 43), ADJ( 54));
      init_color(NC_COL_BASE02   , ADJ(  7), ADJ( 54), ADJ( 66));
      init_color(NC_COL_BASE01   , ADJ( 88), ADJ(110), ADJ(117));
      init_color(NC_COL_BASE00   , ADJ(101), ADJ(123), ADJ(131));
      init_color(NC_COL_BASE0    , ADJ(131), ADJ(148), ADJ(150));
      init_color(NC_COL_BASE1    , ADJ(147), ADJ(161), ADJ(161));
      init_color(NC_COL_BASE2    , ADJ(238), ADJ(232), ADJ(213));
      init_color(NC_COL_BASE3    , ADJ(253), ADJ(246), ADJ(227));
      init_color(NC_COL_YELLOW   , ADJ(181), ADJ(137), ADJ(  0));
      init_color(NC_COL_ORANGE   , ADJ(203), ADJ( 75), ADJ( 22));
      init_color(NC_COL_RED      , ADJ(220), ADJ( 50), ADJ( 47));
      init_color(NC_COL_MAGENTA  , ADJ(211), ADJ( 54), ADJ(130));
      init_color(NC_COL_VIOLET   , ADJ(108), ADJ(113), ADJ(196));
      init_color(NC_COL_BLUE     , ADJ( 38), ADJ(139), ADJ(210));
      init_color(NC_COL_CYAN     , ADJ( 42), ADJ(161), ADJ(152));
      init_color(NC_COL_GREEN    , ADJ(133), ADJ(153), ADJ(  0));
#undef ADJ

      int i;
      int j;

      if (1) {
         for (i = 0; i < 16; i++) {
            init_pair(NC_COL_BASE03 + i, NC_CPAIR_BASE03 + i, COLOR_BLACK);
         }
      } else {
         for (i = 0; i < 16; i++) {
            for (j = 0; j < 16; j++) {
               init_pair((i << 4) + j + 16, i + 128, j + 128);
            }
         }
      }

#undef ADJ
   } else {
      init_pair(COLOR_BLACK,   COLOR_BLACK,   -1);
      init_pair(COLOR_RED,     COLOR_RED,     -1);
      init_pair(COLOR_GREEN,   COLOR_GREEN,   -1);
      init_pair(COLOR_YELLOW,  COLOR_YELLOW,  -1);
      init_pair(COLOR_BLUE,    COLOR_BLUE,    -1);
      init_pair(COLOR_MAGENTA, COLOR_MAGENTA, -1);
      init_pair(COLOR_CYAN,    COLOR_CYAN,    -1);
      init_pair(COLOR_WHITE,   COLOR_WHITE,   -1);
   }
   return 0;
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_panel_destroy_all --
 *
 *---------------------------------------------------------------------
 */

static void
ncui_panel_destroy_all(void)
{
   while (!circlist_empty(btc->ui->panelList)) {
      struct circlist_item *li = btc->ui->panelList;
      struct ncpanel *p;

      p = GET_PANEL(li);
      circlist_delete_item(&btc->ui->panelList, li);
      ncui_destroy_panel(p);
   }
   btc->ui->panelTop = NULL;
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_tx_update --
 *
 *---------------------------------------------------------------------
 */

void
ncui_tx_update(void)
{
   struct ncpanel *panel = ncui_get_panel_by_type(PANEL_TX);
   struct bitcui_tx *tx_info = btcui->tx_info;
   WINDOW *win = panel->window;
   int64 balance = 0;
   int i;

   ASSERT(mutex_islocked(btcui->lock));

   werase(win);
   for (i = 0; i < btcui->tx_num; i++) {
      size_t pendingLen = 0;
      size_t tslen;
      int y;
      char *ts;

      y = btcui->tx_num - 1 - i;

      ts = print_time_local(tx_info[i].timestamp, "%c");
      tslen = strlen(ts);

      wattron(win, PAIR_CYAN);
      mvwprintw(win, y, 1, "%3u", i);
      wattroff(win, PAIR_CYAN);
      mvwaddch(win,  y, 5, ACS_VLINE);
      mvwprintw(win, y, 7, "%s", ts);
      free(ts);

      // value
      mvwaddch(win,  y, 7 + tslen + 1, ACS_VLINE);
      if (tx_info[i].value > 0) {
         wattron(win, PAIR_GREEN);
      } else {
         wattron(win, PAIR_MAGENTA);
      }
      mvwprintw(win, y, 7 + tslen + 3, "%+.8f", tx_info[i].value / ONE_BTC);
      if (tx_info[i].value > 0) {
         wattroff(win, PAIR_GREEN);
      } else {
         wattroff(win, PAIR_MAGENTA);
      }

      mvwaddch(win,  y, 7 + tslen + 15, ACS_VLINE);

      balance += tx_info[i].value;

      // balance
      mvwprintw(win, y, 7 + tslen + 17, "%.8f", balance / ONE_BTC);
      mvwaddch(win,  y, 7 + tslen + 28, ACS_VLINE);

      wattron(win, PAIR_MAGENTA);
      if (tx_info[i].blockHeight == -1) {
         mvwprintw(win, y, 7 + tslen + 30, "** pending **");
         pendingLen = 14;
      } else {
         uint32 conf = btcui->height - tx_info[i].blockHeight + 1;
         if (conf < 6) {
            mvwprintw(win, y, 7 + tslen + 30, "** %d conf **", conf);
            pendingLen = 14;
         }
      }
      wattroff(win, PAIR_MAGENTA);

      mvwprintw(win, y, 7 + tslen + pendingLen + 30, "%s",
                tx_info[i].desc    ? tx_info[i].desc : "");
   }
   panel->num_lines = btcui->tx_num;

   ncui_panel_check_refresh(panel);
   ncui_dashboard_update();
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_fx_update --
 *
 *---------------------------------------------------------------------
 */

void
ncui_fx_update(void)
{
   struct ncpanel *panel = ncui_get_panel_by_type(PANEL_FX);
   WINDOW *win = panel->window;
   int off_x = 10;
   int off_y = 3;
   int i;

   ASSERT(mutex_islocked(btcui->lock));

   werase(win);

   wattron(win, PAIR_YELLOW);
   mvwprintw(win, 0, off_x + 1, "source: %s", btcui->fx_provider);
   mvwprintw(win, 1, off_x + 1, "(updated every %u min)", btcui->fxPeriodMin);
   wattroff(win, PAIR_YELLOW);

   for (i = 0; i < btcui->fx_num; i++) {
      char *symbol = btcui->fx_pairs[i].symbol;;
      char *name   = btcui->fx_pairs[i].name;;
      double value = btcui->fx_pairs[i].value;;

      /*
       * While we're waiting for wide-character support in ncurses..
       */
      if (strcasecmp(name, "THB") == 0 ||
          strcasecmp(name, "PLN") == 0 ||
          strcasecmp(name, "CNY") == 0 ||
          strcasecmp(name, "JPY") == 0 ||
          strcasecmp(name, "GBP") == 0 ||
          strcasecmp(name, "EUR") == 0) {
         symbol = name;
      }
      wattron(win, PAIR_GREEN);
      mvwprintw(win, off_y + i, off_x + 1, "BTC/%s", name);
      wattroff(win, PAIR_GREEN);
      mvwaddch(win,  off_y + i, off_x +  9, '=');
      mvwprintw(win, off_y + i, off_x + 11, "%13.6f", value);
      mvwprintw(win, off_y + i, off_x + 25, "%s", symbol);
   }
   panel->num_lines = btcui->fx_num + off_y;

   ncui_panel_check_refresh(panel);
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_get_version_str --
 *
 *---------------------------------------------------------------------
 */

static char *
ncui_get_version_str(const char *versionStr)
{
   uint32 v0, v1, v2, v3;
   int n;

   n = sscanf(versionStr, "/Satoshi:%u.%u.%u/", &v0, &v1, &v2);
   if (n == 3) {
      return safe_asprintf("%u.%u.%u", v0, v1, v2);
   }
   n = sscanf(versionStr, "/Satoshi:%u.%u.%u.%u/", &v0, &v1, &v2, &v3);
   if (n == 4) {
      return safe_asprintf("%u.%u.%u.%u", v0, v1, v2, v3);
   }
   return safe_strdup(versionStr);
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_get_city_str --
 *
 *---------------------------------------------------------------------
 */

static char *
ncui_get_city_str(const struct ipinfo_entry *entry)
{
   char cityStr[128];

   if (entry == NULL || entry->city == NULL) {
      return NULL;
   }
   if (strcmp(entry->country_code, "US") == 0
       && entry->region_code) {
      snprintf(cityStr, sizeof cityStr, "%s, %s",
               entry->city, entry->region_code);
   } else {
      snprintf(cityStr, sizeof cityStr, "%s", entry->city);
   }
   return safe_strdup(cityStr);
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_peers_update --
 *
 *---------------------------------------------------------------------
 */

void
ncui_peers_update(void)
{
   struct ncpanel *panel = ncui_get_panel_by_type(PANEL_PEERS);
   WINDOW *win = panel->window;
   struct ipinfo_entry *entry;
   size_t ver_len = 0;
   size_t host_len = 0;
   char *v;
   int i;

   ASSERT(mutex_islocked(btcui->lock));

   for (i = 0; i < btcui->peer_num; i++) {
      v = ncui_get_version_str(btcui->peer_info[i].versionStr);
      if (v) {
         ver_len = MAX(ver_len, strlen(v));
         free(v);
      }
      entry = ipinfo_get_entry(&btcui->peer_info[i].saddr);
      if (entry && entry->hostname) {
         host_len = MAX(host_len, strlen(entry->hostname));
      }
   }

   werase(win);
   for (i = 0; i < btcui->peer_num; i++) {
      wattron(win, PAIR_GREEN);
      mvwprintw(win, i, 1, "%s", btcui->peer_info[i].host);
      wattroff(win, PAIR_GREEN);
      mvwaddch(win,  i, 17, ACS_VLINE);
      v = ncui_get_version_str(btcui->peer_info[i].versionStr);
      wattron(win, PAIR_YELLOW);
      mvwprintw(win, i, 19, "%s", v);
      free(v);
      wattroff(win, PAIR_YELLOW);
      mvwaddch(win,  i, 20 + ver_len, ACS_VLINE);

      entry = ipinfo_get_entry(&btcui->peer_info[i].saddr);
      if (entry && entry->hostname) {
         mvwprintw(win, i, 22 + ver_len, "%s", entry->hostname);
      }
      mvwaddch(win,  i, 23 + ver_len + host_len, ACS_VLINE);
      if (entry && entry->country_code) {
         mvwprintw(win, i, 25 + ver_len + host_len, "%s", entry->country_code);
      }
      mvwaddch(win,  i, 28 + ver_len + host_len, ACS_VLINE);
      if (entry == NULL || entry->hostname == NULL) {
         continue;
      }
      v = ncui_get_city_str(entry);
      if (v) {
         mvwprintw(win, i, 30 + ver_len + host_len, "%s", v);
         free(v);
      }
   }
   panel->num_lines = btcui->peer_num;

   ncui_panel_check_refresh(panel);
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_wallet_update --
 *
 *---------------------------------------------------------------------
 */

void
ncui_wallet_update(void)
{
   struct ncpanel *panel = ncui_get_panel_by_type(PANEL_WALLET);
   WINDOW *win = panel->window;
   int i;

   ASSERT(mutex_islocked(btcui->lock));

   for (i = 0; i < btcui->addr_num; i++) {
      wattron(win, PAIR_GREEN);
      mvwprintw(win, i, 1, "%3u", i);
      wattroff(win, PAIR_GREEN);
      mvwaddch(win,  i, 5, ACS_VLINE);
      mvwprintw(win, i, 7, "%s", btcui->addr_info[i].addr);
      mvwaddch(win,  i, 42, ACS_VLINE);
      mvwprintw(win, i, 44, "%s", btcui->addr_info[i].desc);
   }
   panel->num_lines = btcui->addr_num;

   ncui_panel_check_refresh(panel);
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_is_pfx_char --
 *
 *---------------------------------------------------------------------
 */

static bool
ncui_is_pfx_char(char c)
{
   return (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_log_cb --
 *
 *---------------------------------------------------------------------
 */

void
ncui_log_cb(const char *ts,
            const char *str,
            void *clientData)
{
   struct ncpanel *panel = ncui_get_panel_by_type(PANEL_LOG);
   WINDOW *win = panel->window;
   size_t tslen = strlen(ts);
   size_t slen  = strlen(str);
   size_t i;
   size_t e = 0;
   bool found = 0;

   for (i = 0; i < slen; i++) {
      if (str[i] != ':' && !ncui_is_pfx_char(str[i])) {
         break;
      }
      if (str[i] == ':' && i < slen && str[i + 1] == ' ' && i < 8) {
         e = i;
         found = 1;
         break;
      }
   }

   ASSERT(mutex_islocked(btcui->lock));

   wmove(win, 0, 0);
   scrollok(win, true);
   wscrl(win, -1);
   wattron(win, PAIR_GREEN);
   mvwprintw(win, 0, 0, "%s", ts);
   wattroff(win, PAIR_GREEN);
   mvwaddch(win,  0, tslen, ACS_VLINE);
   if (found) {
      wattron(win, PAIR_MAGENTA);
      for (i = 0; i <= e; i++ ) {
         mvwprintw(win, 0, tslen + 1 + i, "%c", str[i]);
      }
      wattroff(win, PAIR_MAGENTA);
      mvwprintw(win, 0, tslen + i + 2, "%s", str + i + 1);
   } else {
      mvwprintw(win, 0, tslen + 1, "%s", str);
   }
   panel->num_lines = MIN(panel->max_lines, panel->num_lines + 1);

   ncui_panel_check_refresh(panel);
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_blocklist_update --
 *
 *---------------------------------------------------------------------
 */

static void
ncui_blocklist_update(void)
{
   struct ncpanel *panel = ncui_get_panel_by_type(PANEL_BLOCKLIST);
   WINDOW *win = panel->window;
   int last = -1;

   ASSERT(mutex_islocked(btcui->lock));

   while (btcui->blockConsIdx != btcui->blockProdIdx) {
      uint256 *hash;
      uint32 timestamp;
      int height;
      char *ts;
      bool orphan;

      btcui->blockConsIdx = (btcui->blockConsIdx + 1) % ARRAYSIZE(btcui->blocks);

      hash      = &btcui->blocks[btcui->blockConsIdx].hash;
      height    =  btcui->blocks[btcui->blockConsIdx].height;
      timestamp =  btcui->blocks[btcui->blockConsIdx].timestamp;

      ts = print_time_local_short(timestamp);
      orphan = last != -1 && height != last + 1;

      wmove(win, 0, 0);
      scrollok(win, true);
      wscrl(win, -1);
      wattron(win, PAIR_GREEN);
      wattron(win, orphan ? PAIR_RED : PAIR_GREEN);
      mvwprintw(win, 0, 1, "%6d", height);
      wattroff(win, orphan ? PAIR_RED : PAIR_GREEN);
      mvwaddch(win,  0, 8, ACS_VLINE);
      mvwprintw(win, 0, 10, "%s", ts);
      mvwaddch(win,  0, 26, ACS_VLINE);
      mvwprintw(win, 0, 28, "%s", uint256_to_str(hash));
      free(ts);
      panel->num_lines = MIN(panel->max_lines, panel->num_lines + 1);
      last = height;
   }

   ncui_panel_check_refresh(panel);
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_tx_form_create --
 *
 *---------------------------------------------------------------------
 */

static void
ncui_tx_form_create(struct ncui *ncui)
{
   FIELD **field = ncui->field;
   int rows;
   int cols;

                                                // h   w  r   c
   field[TX_FIELD_ADDR_LABEL]          = new_field(1,  8, 0,  2, 0, 0);
   field[TX_FIELD_ADDR]                = new_field(1, 35, 0, 12, 0, 0);
   field[TX_FIELD_LABEL_LABEL ]        = new_field(1,  6, 2,  4, 0, 0);
   field[TX_FIELD_LABEL]               = new_field(1, 35, 2, 12, 0, 0);
   field[TX_FIELD_AVAILABLE_LABEL]     = new_field(1, 11, 4,  7, 0, 0);
   field[TX_FIELD_AVAILABLE]           = new_field(1, 14, 4, 18, 0, 0);
   field[TX_FIELD_AVAILABLE_BTC_LABEL] = new_field(1,  3, 4, 33, 0, 0);
   field[TX_FIELD_AMOUNT_LABEL]        = new_field(1,  8, 6, 10, 0, 0);
   field[TX_FIELD_AMOUNT]              = new_field(1, 14, 6, 18, 0, 0);
   field[TX_FIELD_AMOUNT_BTC_LABEL]    = new_field(1,  3, 6, 33, 0, 0);
   field[TX_FIELD_CANCEL]              = new_field(1,  8, 9, 13, 0, 0);
   field[TX_FIELD_OK]                  = new_field(1,  4, 9, 31, 0, 0);
   field[TX_FIELD_LAST]                = NULL;

   set_field_buffer(field[TX_FIELD_ADDR_LABEL],          0, "address:");
   set_field_buffer(field[TX_FIELD_LABEL_LABEL],         0, "label:");
   set_field_buffer(field[TX_FIELD_AVAILABLE_LABEL],     0, "available:");
   set_field_buffer(field[TX_FIELD_AVAILABLE_BTC_LABEL], 0, "BTC");
   set_field_buffer(field[TX_FIELD_AMOUNT_LABEL],        0, "amount:");
   set_field_buffer(field[TX_FIELD_AMOUNT_BTC_LABEL],    0, "BTC");
   set_field_buffer(field[TX_FIELD_CANCEL],              0, "Cancel");
   set_field_buffer(field[TX_FIELD_OK],                  0, "OK");

   static char availStr[64];
   snprintf(availStr, sizeof availStr, "%.8f",
            ncui_get_max_tx_amount() / ONE_BTC);
   set_field_buffer(field[TX_FIELD_AVAILABLE], 0, availStr);

   set_field_back(field[TX_FIELD_ADDR],   A_UNDERLINE);
   set_field_back(field[TX_FIELD_LABEL],  A_UNDERLINE);
   set_field_back(field[TX_FIELD_AMOUNT], A_UNDERLINE);

   set_field_back(field[TX_FIELD_CANCEL], A_REVERSE);
   set_field_back(field[TX_FIELD_OK],     A_REVERSE);

   field_opts_on(field[TX_FIELD_ADDR],   O_PUBLIC);
   field_opts_on(field[TX_FIELD_LABEL],  O_PUBLIC);
   field_opts_on(field[TX_FIELD_AMOUNT], O_PUBLIC);

   field_opts_on(field[TX_FIELD_ADDR],   O_EDIT);
   field_opts_on(field[TX_FIELD_LABEL],  O_EDIT);
   field_opts_on(field[TX_FIELD_AMOUNT], O_EDIT);

   field_opts_off(field[TX_FIELD_ADDR_LABEL],       O_ACTIVE);
   field_opts_off(field[TX_FIELD_LABEL_LABEL],      O_ACTIVE);
   field_opts_off(field[TX_FIELD_AMOUNT_LABEL],     O_ACTIVE);
   field_opts_off(field[TX_FIELD_AMOUNT_BTC_LABEL], O_ACTIVE);
   field_opts_off(field[TX_FIELD_AVAILABLE_LABEL],     O_ACTIVE);
   field_opts_off(field[TX_FIELD_AVAILABLE_BTC_LABEL], O_ACTIVE);
   field_opts_off(field[TX_FIELD_AVAILABLE],           O_ACTIVE);

   field_opts_off(field[TX_FIELD_ADDR_LABEL],       O_EDIT);
   field_opts_off(field[TX_FIELD_LABEL_LABEL],      O_EDIT);
   field_opts_off(field[TX_FIELD_AMOUNT_LABEL],     O_EDIT);
   field_opts_off(field[TX_FIELD_AMOUNT_BTC_LABEL], O_EDIT);
   field_opts_off(field[TX_FIELD_CANCEL],           O_EDIT);
   field_opts_off(field[TX_FIELD_OK],               O_EDIT);
   field_opts_off(field[TX_FIELD_AVAILABLE_LABEL],     O_EDIT);
   field_opts_off(field[TX_FIELD_AVAILABLE_BTC_LABEL], O_EDIT);
   field_opts_off(field[TX_FIELD_AVAILABLE],           O_EDIT);

   set_field_back(field[TX_FIELD_ADDR_LABEL],          PAIR_CYAN);
   set_field_back(field[TX_FIELD_LABEL_LABEL],         PAIR_CYAN);
   set_field_back(field[TX_FIELD_AVAILABLE_LABEL],     PAIR_CYAN);
   set_field_back(field[TX_FIELD_AVAILABLE_BTC_LABEL], PAIR_CYAN);
   set_field_back(field[TX_FIELD_AMOUNT_LABEL],        PAIR_CYAN);
   set_field_back(field[TX_FIELD_AMOUNT_BTC_LABEL],    PAIR_CYAN);
   set_field_back(field[TX_FIELD_CANCEL],              PAIR_CYAN);
   set_field_back(field[TX_FIELD_OK],                  PAIR_CYAN);

   ncui->form = new_form(ncui->field);
   scale_form(ncui->form, &rows, &cols);
   ncui->fwin_width  = rows + 6;
   ncui->fwin_height = cols + 4;

   ncui->fwin = newpad(ncui->fwin_width, ncui->fwin_height);
   ncui->fpanel = new_panel(ncui->fwin);
   top_panel(ncui->fpanel);
   update_panels();
   keypad(ncui->fwin, TRUE);
   set_form_win(ncui->form, ncui->fwin);
   set_form_sub(ncui->form, subpad(ncui->fwin, rows, cols, 4, 1));
   box(ncui->fwin, 0, 0);

   curs_set(1);
   ncui->curs_on = 1;
   post_form(ncui->form);

   wattron(ncui->fwin, PAIR_CYAN);
   mvwprintw(ncui->fwin, 2, 20, "PAYMENT");
   wattroff(ncui->fwin, PAIR_CYAN);

   wnoutrefresh(ncui->fwin);
   pos_form_cursor(ncui->form);
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_input_kbd_cb --
 *
 *---------------------------------------------------------------------
 */

static void
ncui_input_kbd_cb(struct ncui *ncui,
                  const char *cmd)
{
   if (strcmp(cmd, ":q") == 0 ||
       strcmp(cmd, ":q!") == 0) {
      bitc_req_stop();
   } else if (strncmp(cmd, ":p ", 3) == 0) {
      bitcui_set_status("hash: %s", cmd + 3);
   } else if (strcmp(cmd, "testform") == 0) {
      ncui_tx_form_create(ncui);
   }
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_create_blocklist --
 *
 *---------------------------------------------------------------------
 */

static struct ncpanel*
ncui_create_blocklist(void)
{
   struct ncpanel *panel;

   panel = ncui_create_panel(1000, 0);
   panel->label = safe_strdup("Blocks");
   panel->select_on = 0;

   return panel;
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_create_tx --
 *
 *---------------------------------------------------------------------
 */

static struct ncpanel*
ncui_create_tx(void)
{
   struct ncpanel *panel;

   panel = ncui_create_panel(100, 0);
   panel->label = safe_strdup("Transactions");
   panel->select_on = 0;

   return panel;
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_create_peers --
 *
 *---------------------------------------------------------------------
 */

static struct ncpanel*
ncui_create_peers(void)
{
   struct ncpanel *panel;

   panel = ncui_create_panel(4000, 0);
   panel->label = safe_strdup("Peers");
   panel->select_on = 0;

   return panel;
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_create_contacts --
 *
 *---------------------------------------------------------------------
 */

static struct ncpanel*
ncui_create_contacts(void)
{
   struct ncpanel *panel;

   panel = ncui_create_panel(50, 0);
   panel->label = safe_strdup("Contacts");
   panel->select_on = 0;

   return panel;
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_create_fx --
 *
 *---------------------------------------------------------------------
 */

static struct ncpanel*
ncui_create_fx(void)
{
   struct ncpanel *panel;

   panel = ncui_create_panel(50, 0);
   panel->label = safe_strdup("FX");
   panel->select_on = 0;

   return panel;
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_create_wallet --
 *
 *---------------------------------------------------------------------
 */

static struct ncpanel*
ncui_create_wallet(void)
{
   struct ncpanel *panel;

   panel = ncui_create_panel(50, 0);
   panel->label = safe_strdup("Wallet");
   panel->select_on = 0;

   return panel;
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_create_log --
 *
 *---------------------------------------------------------------------
 */

static struct ncpanel*
ncui_create_log(void)
{
   struct ncpanel *panel;

   panel = ncui_create_panel(1000, 0);
   panel->label      = safe_strdup("Log");
   panel->destroy_cb = NULL;

   return panel;
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_dashboard_color_test --
 *
 *---------------------------------------------------------------------
 */

static int
ncui_dashboard_color_test(WINDOW *win,
                          int i)
{
   int j;

   i += 2;
   for (j = 0; j < 16; j++) {
      wattron(win, COLOR_PAIR(j));
      mvwprintw(win, i++, 1, "colortest%d", j);
      wattroff(win, COLOR_PAIR(j));
   }
   i -= 16;
   for (j = 0; j < 16; j++) {
      wattron(win, COLOR_PAIR(j));
      wattron(win,A_BOLD);
      mvwprintw(win, i++, 15, "colortest%d", j);
      wattroff(win,A_BOLD);
      wattroff(win, COLOR_PAIR(j));
   }
   return i;
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_dashboard_latest_blocks --
 *
 *---------------------------------------------------------------------
 */

static int
ncui_dashboard_latest_blocks(WINDOW *win,
                             int y,
                             int num_tx)
{
   int last = -1;
   int y0 = y;
   int idx;
   int j;

   if (!bitc_state_ready() || btcui->numBlocks < 12) {
      return y;
   }

   idx = btcui->blockProdIdx;

   for (j = 0; j < 12; j++) {
      uint256 *hash    = &btcui->blocks[idx].hash;
      int height       =  btcui->blocks[idx].height;
      time_t timestamp =  btcui->blocks[idx].timestamp;
      char *ts;
      bool orphan;

      ts = print_time_local(timestamp, "%T");

      orphan = last != -1 && height != last - 1 && (last - height) < 100;
      wattron(win, orphan ? PAIR_RED : PAIR_YELLOW);
      mvwprintw(win, y, 1, "%u", height);
      wattroff(win, orphan ? PAIR_RED : PAIR_YELLOW);
      mvwaddch(win,  y, 8, ACS_VLINE);
      mvwprintw(win, y, 10, "%s", ts);
      mvwaddch(win,  y, 19, ACS_VLINE);
      wattron(win, A_DIM);
      mvwprintw(win, y, 21, "%s", uint256_to_str(hash));
      wattroff(win, A_DIM);
      y++;
      free(ts);
      last = height;

      idx--;
      if (idx < 0) {
         idx = ARRAYSIZE(btcui->blocks) - 1;
      }
   }
   mvwhline(win, y, 0, ACS_HLINE, COLS - 1);
   mvwaddch(win, y, 8, ACS_BTEE);
   mvwaddch(win, y, 19, ACS_PLUS);
   mvwaddch(win, y0 - 1, 8, ACS_TTEE);
   mvwaddch(win, y0 - 1, 19, num_tx > 0 ? ACS_PLUS : ACS_TTEE);
   if (num_tx > 0) {
      mvwaddch(win, y0 - 1, 33, ACS_BTEE);
   }
   y++;
   return y;
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_dashboard_peers --
 *
 *---------------------------------------------------------------------
 */

static int
ncui_dashboard_peers(WINDOW *win,
                     int y)
{
   struct ipinfo_entry *entry;
   size_t host_len = 0;
   size_t ver_len = 0;
   char *v;
   int y0 = y;
   int j;

   ASSERT(mutex_islocked(btcui->lock));
   if (!bitc_state_ready() || btcui->peer_num == 0) {
      return y;
   }

   for (j = 0; j < MIN(10, btcui->peer_num); j++) {
      v = ncui_get_version_str(btcui->peer_info[j].versionStr);
      ver_len = MAX(ver_len, strlen(v));
      free(v);
      entry = ipinfo_get_entry(&btcui->peer_info[j].saddr);
      if (entry && entry->hostname) {
         host_len = MAX(host_len, strlen(entry->hostname));
      }
   }

   for (j = 0; j < MIN(10, btcui->peer_num); j++) {
      mvwprintw(win, y, 2, "%s",  btcui->peer_info[j].host);
      mvwaddch(win,  y, 19, ACS_VLINE);
      wattron(win, PAIR_YELLOW);
      v = ncui_get_version_str(btcui->peer_info[j].versionStr);
      mvwprintw(win, y, 21, "%s", v);
      free(v);
      wattroff(win, PAIR_YELLOW);
      mvwaddch(win, y, 22 + ver_len, ACS_VLINE);

      entry = ipinfo_get_entry(&btcui->peer_info[j].saddr);
      if (entry && entry->hostname) {
         mvwprintw(win, y, 24 + ver_len, "%s", entry->hostname);
      }
      mvwaddch(win, y, 25 + ver_len + host_len, ACS_VLINE);
      if (entry && entry->country_code) {
         mvwprintw(win, y, 27 + ver_len + host_len, "%s", entry->country_code);
      }
      mvwaddch(win, y, 30 + ver_len + host_len, ACS_VLINE);
      if (entry && entry->city) {
         char cityStr[128];
         if (strcmp(entry->country_code, "US") == 0) {
            snprintf(cityStr, sizeof cityStr, "%s, %s",
                     entry->city, entry->region_code);
         } else {
            snprintf(cityStr, sizeof cityStr, "%s", entry->city);
         }
         mvwprintw(win, y, 32 + ver_len + host_len, "%s", cityStr);
      }
      y++;
   }
   mvwhline(win, y, 0, ACS_HLINE, COLS - 1);
   mvwaddch(win, y, 19, ACS_BTEE);
   mvwaddch(win, y,  22 + ver_len, ACS_BTEE);
   mvwaddch(win, y,  25 + ver_len + host_len, ACS_BTEE);
   mvwaddch(win, y,  30 + ver_len + host_len, ACS_BTEE);
   mvwaddch(win, y0 - 1, 22 + ver_len, ACS_TTEE);
   mvwaddch(win, y0 - 1, 25 + ver_len + host_len, ACS_TTEE);
   mvwaddch(win, y0 - 1, 30 + ver_len + host_len, ACS_TTEE);
   y++;
   return y;
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_dashboard_latest_tx --
 *
 *---------------------------------------------------------------------
 */

static int
ncui_dashboard_latest_tx(WINDOW *win,
                         int y,
                         int *num_tx)
{
   struct bitcui_tx *tx_info = btcui->tx_info;
   time_t now;
   bool header = 0;
   int yLabel = y;
   int n = 0;
   int j;

   if (!bitc_state_ready()) {
      return y;
   }

   now = time(NULL);

   for (j = btcui->tx_num - 1; j >= 0; j--) {
      size_t tslen;
      char *ts;

      if (now - tx_info[j].timestamp >= 48 * 60 * 60) {
         continue;
      }
      if (header == 0) {
         y += 1;
         header = 1;
      }
      ts = print_time_local_short(tx_info[j].timestamp);
      tslen = strlen(ts);
      mvwprintw(win, y, 1, "- %s", ts);
      mvwaddch(win,  y, 4 + tslen, ACS_VLINE);
      if (tx_info[j].value > 0) {
         wattron(win, PAIR_GREEN);
      } else {
         wattron(win, PAIR_MAGENTA);
      }
      mvwprintw(win, y, 5 + tslen, " %+.8f ", tx_info[j].value / ONE_BTC);
      if (tx_info[j].value > 0) {
         wattroff(win, PAIR_GREEN);
      } else {
         wattroff(win, PAIR_MAGENTA);
      }
      mvwaddch(win,  y, 5 + tslen + 13, ACS_VLINE);
      if (tx_info[j].blockHeight == -1) {
         wattron(win, PAIR_MAGENTA);
         mvwprintw(win, y, 5 + tslen + 15, "** pending **");
         wattroff(win, PAIR_MAGENTA);
      } else {
         uint32 numConf = btcui->height - tx_info[j].blockHeight + 1;
         mvwprintw(win, y, 5 + tslen + 15, "%3u conf.", numConf);
      }
      y++;
      n++;
      free(ts);
   }
   *num_tx = n;
   if (n > 0) {
      mvwhline(win, y++, 0, ACS_HLINE, COLS - 1);
      mvwprintw(win, yLabel, 1, "%u transaction%s in the past 48h:",
                n, n > 1 ? "s" : "");
   }
   return y;
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_dashboard_balance --
 *
 *---------------------------------------------------------------------
 */

static int
ncui_dashboard_balance(WINDOW *win,
                       int y,
                       int len)
{
   int numUnconf;
   int64 unconf;
   int64 conf;

   if (!bitc_state_ready()) {
      return y;
   }

   ncui_get_balance(&conf, &unconf, &numUnconf);

   if (conf == unconf && conf == 0) {
      mvwprintw(win, y, 1, "BALANCE:");
      wattron(win, PAIR_GREEN);
      mvwprintw(win, y++, 10, "0 BTC");
      wattroff(win, PAIR_GREEN);
   } else {
      char str[64];

      mvwprintw(win, y, 1, "BALANCE: ");
      wattron(win, PAIR_GREEN);
      mvwprintw(win, y, 10, "%.8f BTC", conf / ONE_BTC);
      wattroff(win, PAIR_GREEN);

      snprintf(str, sizeof str, "(%d)", numUnconf);
      mvwprintw(win, y++, 1 + len + 3, " -- num_tx: %u %s",
                btcui->tx_num, numUnconf > 0 ? str : "");

      if (conf != unconf) {
         mvwprintw(win, y, 1, "unconf:  ");
         mvwprintw(win, y++, 10, "%.8f BTC", unconf / ONE_BTC);
      }

      if (btcui->fx_num > 0) {
         mvwprintw(win, y, 1, "value:   ");
         wattron(win, PAIR_GREEN);
         mvwprintw(win, y++, 10, "~ %.2f USD",
                   unconf * btcui->fx_pairs[0].value / ONE_BTC);
         wattroff(win, PAIR_GREEN);
      }
   }
   mvwhline(win, y++, 0, ACS_HLINE, COLS - 1);

   return y;
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_dashboard_header --
 *
 *---------------------------------------------------------------------
 */

static int
ncui_dashboard_header(WINDOW *win,
                      int y,
                      size_t *len)
{
   uint32 timestamp;

   mvwprintw(win, y, 1, "block:   ");

   if (btcui->numBlocks > 0) {

      wattron(win,A_BOLD);
      mvwprintw(win, y, 10, "%s", uint256_to_str(&btcui->blocks[btcui->blockProdIdx].hash));
      wattroff(win,A_BOLD);
   }
   y++;
   timestamp = btcui->blocks[btcui->blockProdIdx].timestamp;
   if (timestamp) {
      char str[80];
      char *ts;

      ts = print_time_local(timestamp, "%c");
      *len = snprintf(str, sizeof str, "last:    %s", ts);
      mvwprintw(win, y, 1, "%s", str);
      mvwprintw(win, y, 1 + *len + 3, " -- height: ");
      wattron(win,A_BOLD);
      mvwprintw(win, y++, 1 + *len + 3 + 12, "%u", btcui->height);
      wattroff(win,A_BOLD);
      free(ts);
   } else {
      mvwprintw(win, y++, 1, "last:");
      *len = 15;
   }
   mvwprintw(win, y, 1, "peers:   %u / %u",
             btcui->num_peers_alive, btcui->num_peers_active);
   mvwprintw(win, y++, 1 + *len + 3, " -- addrs:  %u", btcui->num_addrs);

   mvwhline(win, y++, 0, ACS_HLINE, COLS - 1);

   return y;
}

/*
 *---------------------------------------------------------------------
 *
 * ncui_dashboard_sync_info --
 *
 *---------------------------------------------------------------------
 */

static int
ncui_dashboard_sync_info(WINDOW *win,
                         int y)
{
   if (bitc_state_ready()) {
      return y;
   }

   if (btcui->numhdr < btcui->hdrtot) {
      mvwprintw(win, y++, 1, "catching-up: headers: %u out of %u",
                btcui->numhdr, btcui->hdrtot);
      mvwhline(win, y++, 0, ACS_HLINE, COLS - 1);
   } else if (btcui->blk < btcui->blktot - 1) {
      mvwprintw(win, y++, 1, "catching-up: filtered blocks: %u out of %u",
                btcui->blk, btcui->blktot);
      mvwhline(win, y++, 0, ACS_HLINE, COLS - 1);
   }
   return y;
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_dashboard_update --
 *
 *---------------------------------------------------------------------
 */

static void
ncui_dashboard_update(void)
{
   struct ncpanel *panel = ncui_get_panel_by_type(PANEL_DASHBOARD);
   WINDOW *win;
   size_t len = 0;
   int num_tx = 0;
   int y;

   ASSERT(mutex_islocked(btcui->lock));
   win = panel->window;

   for (y = 0; y < LINES; y++) {
      wmove(win, y, 0);
      wclrtoeol(win);
   }

   mutex_lock(btcui->lock);

   y = 0;

   y = ncui_dashboard_header(win, y, &len);
   y = ncui_dashboard_balance(win, y, len);
   y = ncui_dashboard_sync_info(win, y);
   y = ncui_dashboard_latest_tx(win, y, &num_tx);
   y = ncui_dashboard_latest_blocks(win, y, num_tx);
   y = ncui_dashboard_peers(win, y);

   if (0) {
      y = ncui_dashboard_color_test(win, y);
   }
   mutex_unlock(btcui->lock);

   ncui_panel_check_refresh(panel);
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_create_dashboard --
 *
 *---------------------------------------------------------------------
 */

static struct ncpanel*
ncui_create_dashboard(void)
{
   struct ncpanel *panel;

   panel = ncui_create_panel(50, 0);
   panel->scroll_on = 0; /* no scrolling */
   panel->label     = safe_strdup("Dashboard");

   ncui_dashboard_update();

   return panel;
}


/*
 *---------------------------------------------------------------------
 *
 * NCNPanelInit --
 *
 *---------------------------------------------------------------------
 */

static void
ncui_panel_init(void)
{
   size_t i;

   btc->ui->panelList = NULL;
   btc->ui->panelTop = NULL;
   memset(btc->ui->kbdInput, 0, sizeof btc->ui->kbdInput);
   btc->ui->kbdInputLen = 0;

   for (i = 0; i < ARRAYSIZE(allPanels); i++) {
      struct ncpanel *panel;
      size_t j;

      panel = NULL;
      for (j = 0; j < ARRAYSIZE(panelDescriptors); j++) {
         if (panelDescriptors[j].type == allPanels[i].type) {
            panel = panelDescriptors[j].panelCreate();
            panel->type = allPanels[i].type;
            break;
         }
      }
      ASSERT(panel);

      if (i == 0) {
         btc->ui->panelTop = panel;
      }
   }

   /*
    * All panels created.
    */
   top_panel(btc->ui->panelTop->panel);
   update_panels();

   ncui_redraw();
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_on_panic_cb -- --
 *
 *---------------------------------------------------------------------
 */

static void
ncui_on_panic_cb(void *clientData)
{
   resetty();
   endwin();
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_init --
 *
 *---------------------------------------------------------------------
 */

int
ncui_init(void)
{
   struct ncui *ncui;

   ncui = safe_calloc(1, sizeof *ncui);
   btc->ui = ncui;

   {
      struct sigaction sa = { .sa_handler = ncui_signal_cb };
      sigemptyset(&sa.sa_mask);
      sigaction(SIGWINCH, &sa, NULL);
   }
   ncui_ncurses_init();
   panic_register_cb(ncui_on_panic_cb, NULL);
   ncui_panel_init();

   bitcui_set_status("ncui ready.");
   ncui_redraw();

   ncui_contacts_update();

   return 0;
}


/*
 *---------------------------------------------------------------------
 *
 * ncui_exit --
 *
 *---------------------------------------------------------------------
 */

void
ncui_exit(void)
{
   if (btc->ui == NULL) {
      return;
   }

   ncui_panel_destroy_all();
   curs_set(1);
   resetty();
   endwin();
   memset(btc->ui, 0, sizeof *btc->ui);
   free(btc->ui);
   btc->ui = NULL;
}

