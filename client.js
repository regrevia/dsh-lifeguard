/**
 * 客户端：输入框旁一个内存环，点开是构成表。
 * 数据来自插件自己的两个只读地址，读数不占提示词。环一直转，表只在打开时拉。
 */
window.__ModuleLoader__.load({
  id: 'dsh-lifeguard',
  factory(load) {
    const React = load('react');
    const h = React.createElement;
    const POLL_MS = 5000;
    const SIZE = 16;
    const STROKE = 2.5;
    const RADIUS = (SIZE - STROKE) / 2;
    const CIRCUMFERENCE = 2 * Math.PI * RADIUS;
    const DANGER = 85;
    const WARN = 70;
    const RED = '#e5484d';
    const AMBER = '#d9930d';
    /* 感叹号字号，只给字形用。 */
    const MARK_FONT = 9;
    const PANEL_WIDTH = 320;
    const MARGIN = 8;
    /* 状态词说人话；认不出的不写。 */
    const STATUS = { running: '运行中', stopping: '正在停', finished: '已结束', failed: '已失败', killed: '已终止', stopped: '已停止' };
    const FONT = 12;
    const TITLE_FONT = 14;

    function colorOf(pct) {
      if (pct >= DANGER) return RED;
      if (pct >= WARN) return AMBER;
      return 'currentColor';
    }

    function colorFor(pct) {
      if (pct >= DANGER) return RED;
      if (pct >= WARN) return AMBER;
      return 'var(--dsw-alias-label-tertiary, currentColor)';
    }

    /* 字节换算只做一次，界面上不出现原始字节。 */
    function mb(bytes) {
      const value = (Number(bytes) || 0) / (1024 * 1024);
      return value >= 1000 ? `${(value / 1024).toFixed(1)} GB` : `${Math.round(value)} MB`;
    }

    function shortAge(minutes) {
      const value = Number(minutes) || 0;
      if (value < 1) return '刚刚';
      if (value < 60) return `${value} 分钟前`;
      const hours = Math.round(value / 60);
      return hours < 24 ? `${hours} 小时前` : `${Math.round(hours / 24)} 天前`;
    }

    function Ring(props) {
      const pct = Math.max(0, Math.min(100, props.pct));
      const color = colorOf(pct);
      const danger = pct >= DANGER;
      /* 越松越淡，接近告警才回实色。 */
      const weight = danger ? 1 : pct >= WARN ? 0.8 : pct >= 50 ? 0.5 : 0.32;
      const arc = h('circle', { key: 'arc', cx: SIZE / 2, cy: SIZE / 2, r: RADIUS, fill: 'none', stroke: color, strokeWidth: STROKE, strokeLinecap: 'round', strokeDasharray: CIRCUMFERENCE, strokeDashoffset: CIRCUMFERENCE * (1 - pct / 100), opacity: weight, transform: `rotate(-90 ${SIZE / 2} ${SIZE / 2})` });
      const track = h('circle', { key: 'track', cx: SIZE / 2, cy: SIZE / 2, r: RADIUS, fill: 'none', stroke: 'currentColor', strokeWidth: STROKE, opacity: 0.22 });
      const parts = [track, arc];
      /* 字号 9、抬半像素：感叹号才不压到圈线。 */
      if (danger) parts.push(h('text', { key: 'mark', x: SIZE / 2, y: SIZE / 2 - 0.5, textAnchor: 'middle', dominantBaseline: 'central', fontSize: MARK_FONT, fontWeight: 800, fill: color }, '!'));
      return h('svg', { width: SIZE, height: SIZE, viewBox: `0 0 ${SIZE} ${SIZE}`, 'aria-hidden': true, style: { display: 'block', flex: 'none' } }, parts);
    }

    /* 一条占比：名字在左，数字在右，细条在下面。 */
    function ShareRow(props) {
      const { name, share, detail, value, onClick, expanded, muted } = props;
      const headStyle = { display: 'flex', alignItems: 'baseline', gap: 8 };
      const nameStyle = { flex: '1 1 auto', minWidth: 0, fontSize: FONT, lineHeight: 1.5, color: 'var(--dsw-alias-label-primary, inherit)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', opacity: muted ? 0.6 : 1 };
      const valueStyle = { flex: 'none', fontSize: FONT, lineHeight: 1.5, fontVariantNumeric: 'tabular-nums', color: 'var(--dsw-alias-label-secondary, inherit)' };
      const head = h('div', { style: headStyle }, h('span', { style: nameStyle }, name), h('span', { style: valueStyle }, value));
      const barStyle = { marginTop: 4, height: 3, borderRadius: 2, background: 'var(--dsw-alias-fill-l2, rgba(128,128,128,0.22))', overflow: 'hidden' };
      const fillStyle = { width: `${Math.max(1, Math.min(100, share))}%`, height: '100%', borderRadius: 2, background: colorFor(share) };
      const bar = h('div', { style: barStyle }, h('div', { style: fillStyle }));
      const body = [head, bar];
      if (detail) body.push(h('div', { style: { marginTop: 3, fontSize: FONT, lineHeight: 1.5, color: 'var(--dsw-alias-label-tertiary, inherit)' } }, detail));
      const style = { display: 'block', width: '100%', padding: '7px 8px', margin: 0, border: 0, borderRadius: 'var(--dsw-radius-sm, 6px)', background: expanded ? 'var(--dsw-alias-fill-l2, rgba(128,128,128,0.14))' : 'transparent', textAlign: 'left', font: 'inherit', cursor: onClick ? 'pointer' : 'default' };
      return onClick ? h('button', { type: 'button', onClick, 'aria-expanded': Boolean(expanded), style }, body) : h('div', { style }, body);
    }

    function JobLine(props) {
      const job = props.job;
      const status = STATUS[job.status] || '';
      const bits = [status, job.retained ? `输出 ${mb(job.retained)}` : ''].filter(Boolean).join(' · ');
      const lineStyle = { display: 'flex', alignItems: 'baseline', gap: 8, padding: '4px 8px 4px 16px', fontSize: FONT, lineHeight: 1.5 };
      const labelStyle = { flex: '1 1 auto', minWidth: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: 'var(--dsw-alias-label-secondary, inherit)' };
      const bitsStyle = { flex: 'none', color: 'var(--dsw-alias-label-tertiary, inherit)', fontVariantNumeric: 'tabular-nums' };
      return h('div', { style: lineStyle }, h('span', { style: labelStyle }, job.label), h('span', { style: bitsStyle }, bits));
    }

    function Panel(props) {
      const { state, breakdown, open, anchor, onClose } = props;
      const [at, setAt] = React.useState(null);
      const [expandedId, setExpandedId] = React.useState('');
      const totalMB = breakdown && Number.isFinite(breakdown.estimatedMB) ? breakdown.estimatedMB : 0;
      const sessions = breakdown && Array.isArray(breakdown.sessions) ? breakdown.sessions : [];

      /* 锚在圈上方：不让面板飞出屏幕，也不跟着滚动漂。 */
      const place = () => {
        const rect = anchor || { left: 16, top: window.innerHeight - 64 };
        const width = Math.min(PANEL_WIDTH, window.innerWidth - MARGIN * 2);
        const left = Math.max(MARGIN, Math.min(rect.left, window.innerWidth - width - MARGIN));
        return { position: 'fixed', left, bottom: Math.max(MARGIN, window.innerHeight - rect.top + 8), width, zIndex: 100 };
      };
      const [pos] = React.useState(place);

      React.useEffect(() => {
        const element = at;
        function away(event) {
          if (element && element.contains(event.target)) return;
          onClose();
        }
        function escape(event) {
          if (event.key === 'Escape') onClose();
        }
        document.addEventListener('mousedown', away, true);
        document.addEventListener('keydown', escape, true);
        return () => {
          document.removeEventListener('mousedown', away, true);
          document.removeEventListener('keydown', escape, true);
        };
      }, [at, onClose]);

      const rows = sessions.map((session) => {
        const share = totalMB > 0 ? (session.estimateMB / totalMB) * 100 : 0;
        const name = session.title || session.project || session.id.slice(0, 8);
        const detail = `${shortAge(session.ageMin)} · 估 ${session.estimateMB} MB`;
        const expanded = expandedId === session.id;
        const clickable = session.jobs && session.jobs.length > 0;
        const element = h(ShareRow, { key: session.id, name, share, detail, value: `${Math.round(share)}%`, onClick: clickable ? () => setExpandedId(expanded ? '' : session.id) : undefined, expanded });
        if (!expanded) return element;
        return h(React.Fragment, { key: session.id }, element, session.jobs.map((job, index) => h(JobLine, { key: `${session.id}:${index}`, job })));
      });

      const headStyle = { padding: '10px 12px 8px' };
      const rowStyle = { display: 'flex', alignItems: 'baseline', gap: 8 };
      const titleStyle = { flex: '1 1 auto', fontSize: TITLE_FONT, fontWeight: 600, color: 'var(--dsw-alias-label-primary, inherit)' };
      const figureStyle = { fontSize: FONT, fontVariantNumeric: 'tabular-nums', color: 'var(--dsw-alias-label-secondary, inherit)' };
      const noteStyle = { marginTop: 2, fontSize: FONT, lineHeight: 1.5, color: 'var(--dsw-alias-label-tertiary, inherit)' };
      const head = h('div', { style: headStyle },
        h('div', { style: rowStyle }, h('span', { style: titleStyle }, '内存构成'), h('span', { style: figureStyle }, `${state.heapMB} / ${state.wallMB} MB`)),
        h('div', { style: noteStyle }, sessions.length ? `按记录体积折算，估合计 ${mb(totalMB * 1024 * 1024)}` : '读数还没到'),
      );
      const list = sessions.length ? h('div', { style: { maxHeight: 'min(420px, 60vh)', overflowY: 'auto', padding: '0 4px 6px' } }, rows) : null;
      const foot = sessions.length && breakdown.staleCount ? h('div', { style: { padding: '0 12px 10px', fontSize: FONT, lineHeight: 1.5, color: 'var(--dsw-alias-label-tertiary, inherit)' } }, `另有 ${breakdown.staleCount} 个会话没打开，不占内存`) : null;

      const panelStyle = Object.assign({}, pos, { maxHeight: 'min(520px, 80vh)', overflow: 'hidden', display: 'flex', flexDirection: 'column', background: 'var(--dsw-alias-specific-menu, var(--dsw-alias-fill-l1, Canvas))', border: '1px solid var(--dsw-alias-border-l1, rgba(128,128,128,0.2))', borderRadius: 'var(--dsw-radius-md, 10px)', boxShadow: 'var(--dsw-elevation-prominent, 0 8px 28px rgba(0,0,0,0.28))', opacity: open ? 1 : 0, transition: 'opacity 120ms ease' });
      return h('div', { ref: (node) => setAt(node), role: 'dialog', 'aria-label': '内存构成', style: panelStyle }, head, list, foot);
    }

    function Health() {
      const [state, setState] = React.useState(null);
      const [breakdown, setBreakdown] = React.useState(null);
      const [open, setOpen] = React.useState(false);
      const [anchor, setAnchor] = React.useState(null);
      const button = React.useRef(null);

      /* 环的读数：五秒一次，失败保留上一次，不清屏。 */
      React.useEffect(() => {
        let alive = true;
        const pull = () => {
          Promise.resolve()
            .then(() => fetch('/lifeguard/health', { cache: 'no-store' }))
            .then((response) => (response.ok ? response.json() : null))
            .then((payload) => {
              if (alive && payload && payload.enabled) setState(payload);
            })
            .catch(() => {
              /* 没挂上就保持原样：消失的指示器分不出「没事」和「坏了」 */
            });
        };
        pull();
        const timer = setInterval(pull, POLL_MS);
        return () => {
          alive = false;
          clearInterval(timer);
        };
      }, []);

      /* 构成只在打开时拉。 */
      React.useEffect(() => {
        if (!open) return undefined;
        let alive = true;
        const pull = () => {
          Promise.resolve()
            .then(() => fetch('/lifeguard/memory', { cache: 'no-store' }))
            .then((response) => (response.ok ? response.json() : null))
            .then((payload) => {
              if (alive && payload && payload.enabled) setBreakdown(payload);
            })
            .catch(() => {
              /* 拿不到就保持上一次的构成 */
            });
        };
        pull();
        const timer = setInterval(pull, POLL_MS);
        return () => {
          alive = false;
          clearInterval(timer);
        };
      }, [open]);

      const known = Boolean(state) && Number.isFinite(state.pct);
      const pct = known ? state.pct : 0;
      const color = known && pct >= DANGER ? RED : known && pct >= WARN ? AMBER : 'inherit';
      /* 数字跟着环一起退：低压淡，接近上限才实。 */
      const readout = !known ? 0.5 : pct >= DANGER ? 1 : pct >= WARN ? 0.8 : pct >= 50 ? 0.6 : 0.42;
      const toggle = () => {
        const rect = button.current ? button.current.getBoundingClientRect() : null;
        setAnchor(rect ? { left: rect.left, top: rect.top } : null);
        setOpen((was) => !was);
      };

      const triggerStyle = { position: 'relative', display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: FONT, lineHeight: 1, color, whiteSpace: 'nowrap', userSelect: 'none', opacity: known ? 1 : 0.5, cursor: 'pointer', padding: 0, margin: 0, border: 0, background: 'transparent', font: 'inherit' };
      const label = known ? `内存占用 ${state.heapMB}/${state.wallMB} MB，点开看构成` : '内存读数还没到';
      return h(React.Fragment, null,
        h('button', { ref: button, type: 'button', onClick: toggle, 'aria-haspopup': 'dialog', 'aria-expanded': open, 'aria-label': label, style: triggerStyle },
          h('span', { style: { opacity: 0.66 } }, '内存'),
          h(Ring, { pct }),
          h('span', { style: { fontVariantNumeric: 'tabular-nums', opacity: readout } }, known ? `${pct}%` : '–'),
        ),
        open && known ? h(Panel, { state, breakdown, open, anchor, onClose: () => setOpen(false) }) : null,
      );
    }

    return {
      inject: ['slots'],
      apply(ctx) {
        ctx.slots.inject('conversation.composer.dock', () =>
          ctx.slots.register({ name: 'conversation.composer.dock', id: 'lifeguard-health', order: 40 }, Health),
        );
      },
    };
  },
});
