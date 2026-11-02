/* Browser half: only non-secret configuration uses DSH's revisioned settings API. */
window.__ModuleLoader__.load({
  id: '@guoxianzhe/dsh-oauth',
  factory(require) {
    const exports = {};
    Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' });
    const React = require('react');
    const h = React.createElement;
    function apply(ctx) {
      const form = ctx.configForms.get('dsh-oauth');
      function Page(props) {
        const current = React.useSyncExternalStore(listener => form.subscribe(listener), () => form.getSnapshot());
        const [url, setUrl] = React.useState('');
        const [scope, setScope] = React.useState('');
        const [origins, setOrigins] = React.useState('');
        const [loopback, setLoopback] = React.useState(false);
        const [message, setMessage] = React.useState('');
        const [saving, setSaving] = React.useState(false);
        React.useEffect(() => {
          if (!current.value) return;
          setUrl(current.value.url ?? ''); setScope(current.value.scope ?? '');
          setOrigins((current.value.authorizationOrigins ?? []).join('\n'));
          setLoopback(current.value.allowInsecureLoopback ?? false);
        }, [current.revision]);
        if (props.view === 'summary') return 'Browser sign-in for remote MCP services / MCP 浏览器登录';
        const save = async event => {
          event.preventDefault(); setSaving(true); setMessage('');
          try {
            const ok = await form.mutate([
              { op: 'set', path: ['url'], value: url.trim() },
              { op: 'set', path: ['scope'], value: scope.trim() },
              { op: 'set', path: ['authorizationOrigins'], value: origins.split('\n').map(v => v.trim()).filter(Boolean) },
              { op: 'set', path: ['allowInsecureLoopback'], value: loopback },
            ]);
            setMessage(ok ? '已保存。回到对话，调用 mcp__example__oauth_login 开始浏览器登录。' : '保存失败；请刷新设置后核对。');
          } catch { setMessage('保存失败；没有修改令牌或业务授权。'); }
          finally { setSaving(false); }
        };
        const field = (label, value, onChange, multiline = false) => h('label', { style: { display: 'block', margin: '16px 0' } },
          h('span', { style: { display: 'block', marginBottom: 6 } }, label),
          h(multiline ? 'textarea' : 'input', { value, onChange: event => onChange(event.target.value),
            style: { width: '100%', padding: 10, border: '1px solid #999', borderRadius: 6 }, disabled: saving || !current.writable }));
        return h('form', { onSubmit: save, style: { maxWidth: 680 } },
          h('h3', null, 'MCP OAuth'),
          h('p', null, '填写服务地址；不填写密码或令牌。保存后在对话中调用 oauth_login，或使用 DSH 的凭据授权入口。'),
          field('MCP HTTPS URL', url, setUrl), field('OAuth scope（可选）', scope, setScope),
          field('受信任的授权服务器 origin（每行一个，可留空）', origins, setOrigins, true),
          h('label', null, h('input', { type: 'checkbox', checked: loopback,
            onChange: event => setLoopback(event.target.checked), disabled: saving || !current.writable }),
          ' 允许本机 HTTP loopback 测试（正式 HTTPS 服务不要勾选）'),
          h('div', { style: { marginTop: 20 } }, h('button', { type: 'submit', disabled: saving || !current.writable,
            style: { padding: '8px 20px', border: '1px solid #888', borderRadius: 6 } }, saving ? '保存中…' : '保存 MCP 配置')),
          h('p', { role: 'status' }, message || (current.status === 'loading' ? '加载中…' : '')));
      }
      ctx.effect(() => ctx.slots.inject('plugins.bundle.config', () =>
        ctx.slots.register({ name: 'plugins.bundle.config', key: '@guoxianzhe/dsh-oauth' }, Page)), 'dsh-oauth.settings-page');
    }
    exports.apply = apply;
    exports.inject = ['slots', 'configForms'];
    return exports;
  },
});
