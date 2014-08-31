
/*****************************************************************************
 *                                                                           *
 * graphvwr.hpp: generic graphing interface front-end helper class           *
 * (c) 2007-2008 servil                                                      *
 *                                                                           *
 *****************************************************************************/

#ifndef __cplusplus
#error C++ compiler required.
#endif

#ifndef _GRAPHVWR_HPP_ // #pragma once
#define _GRAPHVWR_HPP_

#include "mscrtdbg.h"
#include <stdexcept>
#include <typeinfo>
#include <boost/noncopyable.hpp>
#define NOMINMAX 1
#include <wtypes.h>
#include "idasdk.hpp"
#include "plugsys.hpp"
#include "plugxcpt.hpp"

#if IDA_SDK_VERSION >= 510

class CGraphForm : private boost::noncopyable {
protected:
	// viewer identification
	graph_dispatcher_t *grentry;
	HWND hwnd;
	TForm *form;
	graph_viewer_t *gv;
	netnode id;

private:
	void reset() throw() {
		hwnd = NULL;
		form = NULL;
		gv = NULL;
	}

protected:
	// IDA graphing interface
	virtual bool calculating_layout(mutable_graph_t *g) const {
		_ASSERTE(g != 0);
		//if (g == 0) return false;
		OutputDebugString("%s(...)\n", __FUNCTION__);
		return false;
	}
	virtual void layout_calculated(mutable_graph_t *g) const {
		_ASSERTE(g != 0);
		//if (g == 0) return;
		OutputDebugString("%s(...)\n", __FUNCTION__);
	}
	virtual void changed_graph(mutable_graph_t *g) const {
		_ASSERTE(g != 0);
		//if (g == 0) return;
		OutputDebugString("%s(...)\n", __FUNCTION__);
	}
	virtual bool changed_current(graph_viewer_t *gv, int curnode) const {
		_ASSERTE(gv != 0);
		//if (gv == 0) return false;
		OutputDebugString("%s(..., %i)\n", __FUNCTION__, curnode);
		return true;
	}
	virtual bool clicked(graph_viewer_t *gv, const selection_item_t *current_item) const {
		_ASSERTE(gv != 0);
		//if (gv == 0) return false;
		OutputDebugString("%s(...)\n", __FUNCTION__);
		return true;
	}
	virtual bool dblclicked(graph_viewer_t *gv, const selection_item_t *current_item) const {
		_ASSERTE(gv != 0);
		//if (gv == 0) return false;
		OutputDebugString("%s(...)\n", __FUNCTION__);
		return true;
	}
	virtual bool creating_group(mutable_graph_t *g, intset_t *nodes) const {
		_ASSERTE(g != 0);
		//if (g == 0) return false;
		OutputDebugString("%s(...)\n", __FUNCTION__);
		return true;
	}
	virtual bool deleting_group(mutable_graph_t *g, int old_group) const {
		_ASSERTE(g != 0);
		//if (g == 0) return false;
		//_ASSERTE(abs_node(old_group) < g->size());
		//if (abs_node(old_group) >= g->size()) return false;
		OutputDebugString("%s(..., %i)\n", __FUNCTION__, old_group);
		return true;
	}
	virtual bool group_visibility(mutable_graph_t *g, int group, bool expand) const {
		_ASSERTE(g != 0);
		//if (g == 0) return false;
		//_ASSERTE(abs_node(group) < g->size());
		//if (absnode(group) >= g->size()) return false;
		OutputDebugString("%s(..., %i, %s)\n", __FUNCTION__, group, expand ? "true" : "false");
		return true;
	}
	virtual void gotfocus(graph_viewer_t *gv) const {
		_ASSERTE(gv != 0);
		//if (gv == 0) return;
		OutputDebugString("%s(...)\n", __FUNCTION__);
	}
	virtual void lostfocus(graph_viewer_t *gv) const {
		_ASSERTE(gv != 0);
		//if (gv == 0) return;
		OutputDebugString("%s(...)\n", __FUNCTION__);
	}
	virtual void user_refresh(mutable_graph_t *g) const {
		_ASSERTE(g != 0);
		//if (g == 0) return;
		OutputDebugString("%s(...)\n", __FUNCTION__);
	}
	virtual void user_gentext(mutable_graph_t *g) const {
		_ASSERTE(g != 0);
		//if (g == 0) return;
		OutputDebugString("%s(...)\n", __FUNCTION__);
	}
	virtual void user_text(mutable_graph_t *g, int node, const char **result,
		bgcolor_t *bg_color) const {
		_ASSERTE(g != 0);
		//if (g == 0) return;
		_ASSERTE(abs_node(node) < g->size());
		//if (abs_node(node) >= g->size()) return;
		//OutputDebugString("%s(..., %i, ...)\n", __FUNCTION__, node);
	}
	virtual bool user_size(mutable_graph_t *g, int node, int *cx, int *cy) const {
		_ASSERTE(g != 0);
		//if (g == 0) return false;
		_ASSERTE(abs_node(node) < g->size());
		//if (abs_node(node) >= g->size()) return false;
		//OutputDebugString("%s(..., %i, ...): proposed sizes = (%i, %i)\n",
		//	__FUNCTION__, node, *cx, *cy);
		return false;
	}
	virtual bool user_title(mutable_graph_t *g, int node, rect_t *title_rect,
		int title_bg_color, HDC dc) const {
		_ASSERTE(g != 0);
		//if (g == 0) return false;
		_ASSERTE(abs_node(node) < g->size());
		//if (abs_node(node) >= g->size()) return false;
		_ASSERTE(title_rect != 0);
		//if (title_rect == 0) return false;
		_ASSERTE(dc != NULL);
		//if (dc == NULL) return false;
		OutputDebugString("%s(..., %i, ...)\n", __FUNCTION__, node);
		return false;
	}
	virtual bool user_draw(mutable_graph_t *g, int node, rect_t *node_rect, HDC dc) const {
		_ASSERTE(g != 0);
		//if (g == 0) return false;
		_ASSERTE(abs_node(node) < g->size());
		//if (abs_node(node) >= g->size()) return false;
		_ASSERTE(node_rect != 0);
		//if (node_rect == 0) return false;
		_ASSERTE(dc != NULL);
		//if (dc == NULL) return false;
		//OutputDebugString("%s(..., %i, ...)\n", __FUNCTION__, node);
		return false;
	}
	// result: true to show proposed hint otherwise show default
	virtual bool user_hint(mutable_graph_t *g, int node, const edge_t &edge,
		char **hint) const {
		_ASSERTE(g != 0);
		//if (g == 0) return false;
		_ASSERTE(hint != 0);
		//if (hint == 0) return false;
		OutputDebugString("%s(..., %i, %i, %i, ...)\n", __FUNCTION__, node,
			edge.src, edge.dst);
		return false;
	}
	virtual void destroyed(mutable_graph_t *g) {
		_ASSERTE(g != 0);
		//if (g == 0) return;
		OutputDebugString("%s(...)\n", __FUNCTION__);
	}
	// result: false to cancel graph, true to proceed
	virtual bool created() {
		OutputDebugString("%s(...)\n", __FUNCTION__);
		add_menu_item("Change layout type", change_layout, "L");
		add_menu_item("Go to root", go_root, "R");
		add_menu_item("Locate node by number", go_node, "G");
		fit_window();
		return true;
	}

	static inline int abs_node(int node) throw()
		{ return node & ~COLLAPSED_NODE; }

private:
	static int idaapi dispatcher(void *ud, int code, va_list va) {
		mutable_graph_t *g;
		graph_viewer_t *gv;
		int node;
		selection_item_t *current_item;
		rect_t *rect;
		HDC dc;
		_ASSERTE(ud != 0);
		if (ud != 0) try {
			switch (code) {
				case grcode_calculating_layout:
					// calculating user-defined graph layout
					// in: mutable_graph_t *g
					// out: 0-not implemented
					//      1-graph layout calculated by the plugin
					g = va_argi(va, mutable_graph_t *);
					if (static_cast<CGraphForm *>(ud)->calculating_layout(g))
						return 1;
					break;
				case grcode_layout_calculated:
					// new graph has been set
					// in: mutable_graph_t *g
					// out: must return 0
					g = va_argi(va, mutable_graph_t *);
					static_cast<CGraphForm *>(ud)->layout_calculated(g);
					break;
				case grcode_changed_graph:
					// new graph has been set
					// in: mutable_graph_t *g
					// out: must return 0
					g = va_argi(va, mutable_graph_t *);
					static_cast<CGraphForm *>(ud)->changed_graph(g);
					break;
				case grcode_changed_current:
					// a new graph node became the current node
					// in:  graph_viewer_t *gv
					//      int curnode
					// out: 0-ok, 1-forbid to change the current node
					gv = va_argi(va, graph_viewer_t *);
					node = va_argi(va, int);
					if (!static_cast<CGraphForm *>(ud)->changed_current(gv, node))
						return 1;
					break;
				case grcode_clicked:
					// a graph has been clicked
					// in:  graph_viewer_t *gv
					//      selection_item_t *current_item
					// out: 0-ok, 1-ignore click
					gv = va_argi(va, graph_viewer_t *);
					current_item = va_argi(va, selection_item_t *);
					if (!static_cast<CGraphForm *>(ud)->clicked(gv, current_item))
						return 1;
					break;
				case grcode_dblclicked:
					// a graph node has been double clicked
					// in:  graph_viewer_t *gv
					//      selection_item_t *current_item
					// out: 0-ok, 1-ignore click
					gv = va_argi(va, graph_viewer_t *);
					current_item = va_argi(va, selection_item_t *);
					if (!static_cast<CGraphForm *>(ud)->dblclicked(gv, current_item))
						return 1;
					break;
				case grcode_creating_group: {
					// a group is being created
					// in:  mutable_graph_t *g
					//      intset_t *nodes
					// out: 0-ok, 1-forbid group creation
					g = va_argi(va, mutable_graph_t *);
					intset_t *nodes = va_argi(va, intset_t *);
					_ASSERTE(nodes != 0);
					if (nodes == 0) break;
					if (!static_cast<CGraphForm *>(ud)->creating_group(g, nodes))
						return 1;
					break;
				}
				case grcode_deleting_group:
					// a group is being deleted
					// in:  mutable_graph_t *g
					//      int old_group
					// out: 0-ok, 1-forbid group deletion
					g = va_argi(va, mutable_graph_t *);
					node = va_argi(va, int);
					if (!static_cast<CGraphForm *>(ud)->deleting_group(g, node))
						return 1;
					break;
				case grcode_group_visibility: {
					// a group is being collapsed/uncollapsed
					// in:  mutable_graph_t *g
					//      int group
					//      bool expand
					// out: 0-ok, 1-forbid group modification
					g = va_argi(va, mutable_graph_t *);
					node = va_argi(va, int);
					bool expand = va_argi(va, bool);
					if (!static_cast<CGraphForm *>(ud)->group_visibility(g, node, expand))
						return 1;
					break;
				}
				case grcode_gotfocus:
					// a graph viewer got focus
					// in:  graph_viewer_t *gv
					// out: must return 0
					gv = va_argi(va, graph_viewer_t *);
					static_cast<CGraphForm *>(ud)->gotfocus(gv);
					break;
				case grcode_lostfocus:
					// a graph viewer lost focus
					// in:  graph_viewer_t *gv
					// out: must return 0
					gv = va_argi(va, graph_viewer_t *);
					static_cast<CGraphForm *>(ud)->lostfocus(gv);
					break;
				case grcode_user_refresh:
					// refresh user-defined graph node number and edges
					// in:  mutable_graph_t *g
					// out: success
					g = va_argi(va, mutable_graph_t *);
					static_cast<CGraphForm *>(ud)->user_refresh(g);
					return 1;
				case grcode_user_gentext:
					// generate text for user-defined graph nodes
					// in:  mutable_graph_t *g
					// out: success
					g = va_argi(va, mutable_graph_t *);
					static_cast<CGraphForm *>(ud)->user_gentext(g);
					return 1;
				case grcode_user_text: {
					// retrieve text for user-defined graph node
					// in:  mutable_graph_t *g
					//      int node
					//      const char **result
					//      bgcolor_t *bg_color (maybe NULL)
					// out: success, result must be filled
					// NB: do not use anything calling GDI!
					g = va_argi(va, mutable_graph_t *);
					node = va_argi(va, int);
					const char **result  = va_argi(va, const char **);
					bgcolor_t *bg_color = va_argi(va, bgcolor_t *);
					static_cast<CGraphForm *>(ud)->user_text(g, node, result, bg_color);
					return 1;
				}
				case grcode_user_size: {
					// calculate node size for user-defined graph
					// in:  mutable_graph_t *g
					//      int node
					//      int *cx
					//      int *cy
					// out: 0-did not calculate, ida will use node text size
					//      1-calculated. ida will add node title to the size
					g = va_argi(va, mutable_graph_t *);
					node = va_argi(va, int);
					int *cx = va_argi(va, int *);
					_ASSERTE(cx != 0);
					if (cx == 0) break;
					int *cy = va_argi(va, int *);
					_ASSERTE(cy != 0);
					if (cy == 0) break;
					if (static_cast<CGraphForm *>(ud)->user_size(g, node, cx, cy))
						return 1;
					break;
				}
				case grcode_user_title: {
					// render node title of a user-defined graph
					// in:  mutable_graph_t *g
					//      int node
					//      rect_t *title_rect
					//      int title_bg_color
					//      HDC dc
					// out: 0-did not render, ida will fill it with title_bg_color
					//      1-rendered node title
					g = va_argi(va, mutable_graph_t *);
					node = va_argi(va, int);
					rect = va_argi(va, rect_t *);
					int title_bg_color = va_argi(va, int);
					dc = va_argi(va, HDC);
					if (static_cast<CGraphForm *>(ud)->user_title(g, node, rect, title_bg_color, dc))
						return 1;
					break;
				}
				case grcode_user_draw:
					// render node of a user-defined graph
					// in:  mutable_graph_t *g
					//      int node
					//      rect_t *node_rect
					//      HDC dc
					// out: 0-not rendered, 1-rendered
					// NB: draw only on the specified DC and nowhere else!
					g = va_argi(va, mutable_graph_t *);
					node = va_argi(va, int);
					rect = va_argi(va, rect_t *);
					dc = va_argi(va, HDC);
					if (static_cast<CGraphForm *>(ud)->user_draw(g, node, rect, dc))
						return 1;
					break;
				case grcode_user_hint: {
					// retrieve hint for the user-defined graph
					// in:  mutable_graph_t *g
					//      int mousenode
					//      int mouseedge_src
					//      int mouseedge_dst
					//      char **hint
					// 'hint' must be allocated by qalloc() or qstrdup()
					// out: 0-use default hint, 1-use proposed hint
					g = va_argi(va, mutable_graph_t *);
					node = va_argi(va, int);
					edge_t mouseedge;
					mouseedge.src = va_argi(va, int);
					mouseedge.dst = va_argi(va, int);
					char **hint = va_argi(va, char **);
					if (static_cast<CGraphForm *>(ud)->user_hint(g, node, mouseedge, hint))
						return 1;
					break;
				}
				case grcode_destroyed:
					// graph is being destroyed
					// in:  mutable_graph_t *g
					// out: must return 0
					g = va_argi(va, mutable_graph_t *);
					static_cast<CGraphForm *>(ud)->destroyed(g);
					static_cast<CGraphForm *>(ud)->reset();
					break;
			} // switch event
		} catch (const std::exception &e) {
			warning("%s(..., %i, ...): %s (%s)\n", __FUNCTION__, code,
				e.what(), typeid(e).name());
			//_RPT4(_CRT_ERROR, "%s(..., %i, ...): %s (%s)\n", __FUNCTION__, code,
			//	e.what(), typeid(e).name());
		} catch (...) { }
		return 0;
	} // dispatcher

protected:
	// menu events
	static bool idaapi change_layout(void *ud) {
		_ASSERTE(ud != 0);
		if (ud == 0 || !static_cast<CGraphForm *>(ud)->IsOpen()) return false;
		mutable_graph_t *g = static_cast<CGraphForm *>(ud)->get_viewer_graph();
		if (g == NULL) return false;
		const int code = askbuttons_c("Circle", "Tree", "Digraph",
			g->current_layout == layout_circle ? 1 :
			g->current_layout == layout_tree ? 0 : -1, "Please select layout type");
		const layout_type_t backup = g->current_layout;
		try {
			//static_cast<CGraphForm *>(ud)->grentry(grcode_clear, g);
			switch (code) {
				case 1: // Circle
					if (!static_cast<CGraphForm *>(ud)->grentry(grcode_create_circle_layout,
						g, g->size() * 20, g->size() * 20, g->size() * 20))
						throw logic_error("failed create graph layout layout_circle");
					break;
				case 0: // Tree
					if (askyn_c(0, "AUTOHIDE REGISTRY\nHIDECANCEL\n"
						"Tree layout may cause IDA unrecoverable crash on some\n"
						"kinds of complex graphs, are you sure to proceed?") != 1) return 0;
					if (!static_cast<CGraphForm *>(ud)->grentry(grcode_create_tree_layout, g))
						throw logic_error("failed create graph layout layout_tree");
					break;
				case -1: // Digraph
					if (!static_cast<CGraphForm *>(ud)->grentry(grcode_create_digraph_layout, g))
						throw logic_error("failed create graph layout layout_digraph");
					break;
				default:
					// never should trigger
					g->current_layout = layout_none;
			} // switch
			g->redo_layout();
		} catch (const std::exception &e) {
			msg("%s(...): %s (%s) g->current_layout=%i\n",
				__FUNCTION__, e.what(), typeid(e).name(), g->current_layout);
			_RPT4(_CRT_WARN, "%s(...): %s (%s) g->current_layout=%i\n",
				__FUNCTION__, e.what(), typeid(e).name(), g->current_layout);
			g->current_layout = backup;
			/*re*/throw;
#ifdef _DEBUG
		} catch (...) {
			_RPTF0(_CRT_ASSERT, "never should trigger!");
			g->current_layout = backup;
			return false; ///*re*/throw;
#endif // _DEBUG
		}
		static_cast<CGraphForm *>(ud)->refresh_viewer();
		static_cast<CGraphForm *>(ud)->fit_window();
		return true;
	}

protected:
	static bool idaapi go_root(void *ud) {
		_ASSERTE(ud != 0);
		if (ud == 0 || !static_cast<CGraphForm *>(ud)->IsOpen()) return false;
		mutable_graph_t *g = static_cast<CGraphForm *>(ud)->get_viewer_graph();
		if (g == NULL || static_cast<CGraphForm *>(ud)->grentry(grcode_empty, g))
			return false;
		static_cast<CGraphForm *>(ud)->center_on(0);
		return true;
	}
	static bool idaapi go_node(void *ud) {
		_ASSERTE(ud != 0);
		if (ud == 0 || !static_cast<CGraphForm *>(ud)->IsOpen()) return false;
		mutable_graph_t *g = static_cast<CGraphForm *>(ud)->get_viewer_graph();
		if (g == NULL || static_cast<CGraphForm *>(ud)->grentry(grcode_empty, g))
			return false;
		_ASSERTE(g->size() > 0);
		sval_t node(0);
		if (asklong(&node, "Enter node number (0..%i)", g->size() - 1) != 1
			|| node < 0 || node >= g->size()) return false;
		static_cast<CGraphForm *>(ud)->center_on(static_cast<int>(node));
		return true;
	}

	// global graphing front-ends
private:
	bool create_graph_viewer(int title_height = 0) {
		gv = NULL;
		_ASSERTE(form != NULL);
		if (IsAvail() && form != NULL) {
			grentry(grcode_create_graph_viewer, form, &gv,
				static_cast<uval_t>(id), dispatcher, this, title_height);
			_ASSERTE(gv != NULL);
		}
		return gv != NULL;
	}
protected:
	mutable_graph_t *get_viewer_graph() const {
		mutable_graph_t *g(NULL);
		if (IsOpen()) {
			grentry(grcode_get_viewer_graph, gv, &g);
			_ASSERTE(g != NULL);
		}
		return g;
	}
	inline void set_viewer_graph(mutable_graph_t *g) const
		{ if (IsOpen()) grentry(grcode_set_viewer_graph, gv, g); }
	inline graph_viewer_t *get_graph_viewer() const throw()
		{ return IsOpen() ? gv : NULL; }
	inline void refresh_viewer() const
		{ if (IsOpen()) grentry(grcode_refresh_viewer, gv); }
	inline void fit_window() const
		{ if (IsOpen()) grentry(grcode_fit_window, gv); }
	inline int get_curnode() const
		{ return IsOpen() ? grentry(grcode_get_curnode, gv) : -1; }
	inline void center_on(int node) const
		{ if (IsOpen()) grentry(grcode_center_on, gv, node); }
	inline void set_gli(const graph_location_info_t &gli) const
		{ if (IsOpen()) grentry(grcode_set_gli, gv, &gli); }
	inline bool add_menu_item(const char *title, menu_item_callback_t *callback,
		const char *hotkey = 0, int flags = 0) const {
		return IsOpen() ? grentry(grcode_add_menu_item, gv, title,
			callback, this, hotkey, flags) : false;
	}
	inline bool del_menu_item(const char *title) const
		{ return IsOpen() ? grentry(grcode_del_menu_item, gv, title) : false; }
	inline bool get_selection(screen_graph_selection_t &sgs) const
		{ return IsOpen() ? grentry(grcode_get_selection, gv, &sgs) : false; }
	inline int set_titlebar_height(int height) const
		{ return IsOpen() ? grentry(grcode_set_titlebar_height, gv, height) : -1; }
	void set_node_info(int node, bgcolor_t *pcolor, ea_t *pea2, const char *text) const {
		if (!IsOpen()) return;
		_ASSERTE(node != -1);
		mutable_graph_t *g = get_viewer_graph();
		if (g != NULL) ::set_node_info(g->gid, node, pcolor, pea2, text);
	}
	char *get_node_info(int node, bgcolor_t *pcolor, ea_t *pea) const {
		if (IsOpen()) {
			_ASSERTE(node != -1);
			mutable_graph_t *g = get_viewer_graph();
			if (g != NULL) return ::get_node_info(g->gid, node, pcolor, pea);
		}
		return 0;
	}
	void full_refresh() const {
		mutable_graph_t *g = get_viewer_graph();
		if (g != NULL) grentry(grcode_clear, g); //g->reset();
		refresh_viewer();
		fit_window();
	}

public:
	// construction/destruction
	CGraphForm() : grentry(NULL) {
		reset();
		HMODULE hIdaWll;
#ifdef __X64__ // 64-bit kernel
		if ((hIdaWll = GetModuleHandle("IDA64.WLL")) == NULL)
#endif
		hIdaWll = GetModuleHandle("IDA.WLL");
		_ASSERTE(hIdaWll != NULL);
		if (hIdaWll == NULL) return;
		// ensure kernel >=5.1
		graph_dispatcher_t *const *pgrentry =
			(graph_dispatcher_t *const *)GetProcAddress(hIdaWll, "grentry");
		if (pgrentry != NULL && *pgrentry != NULL
			&& GetProcAddress(hIdaWll, "add_til2") != NULL && id.create())
				grentry = *pgrentry;
	}
	~CGraphForm() {
		Close();
		if (id != BADNODE) id.kill();
	}

	// high-level API
	inline bool IsAvail() const throw() // Is graph form wallet available?
		{ return grentry != NULL; }
	inline bool IsOpen() const throw()  // Is graph form currently open
		{ return IsAvail() && form != NULL && gv != NULL; }
	bool Open(const char *name, int flags = FORM_MDI | FORM_TAB | FORM_MENU | FORM_RESTORE) {
		if (!IsAvail()) return false;
		if (IsOpen()) {
			Refresh();
			return true;
		}
		_ASSERTE(name != 0 && *name != 0);
		form = create_tform(name, &hwnd);
		if (hwnd != NULL && form != NULL && create_graph_viewer()) {
			open_tform(form, flags);
			if (created()) {
				PLUGIN.flags &= ~PLUGIN_UNL;
				return true;
			}
		}
		Close(0);
		return false;
	}
	void Close(int options = FORM_SAVE) {
		if (!IsOpen()) return;
		if (form != NULL) close_tform(form, options);
		reset();
	}
	inline void Refresh() const
		{ if (IsOpen()) full_refresh(); }
	inline void SwitchTo(bool take_focus = true) const
		{ if (IsOpen()) switchto_tform(form, take_focus); }
}; // CGraphForm

#endif // IDA_SDK_VERSION >= 510

#endif // _GRAPHVWR_HPP_
