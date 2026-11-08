// Grants (planning 3 S11): the table of grants and the form that makes one, used by the administration (a global master: any principal, role and zone), by a principal's
// page, and by the "Grants" section of a zone (a domain master: its own zone only, with the policies the page thinks are no wider than its own).  The no-escalation rule is
// the service's (403 `escalation`); the page only offers what is likely to be accepted and shows the refusal.

import { h, link, fill } from '../dom.js';
import { render, timeNode } from '../format.js';
import { field, select, message, problemNodes, confirmButton, busy } from '../widgets.js';
import { placeOnFields } from '../pointer.js';
import { lookupPrincipal, policyWithin } from '../adminlib.js';
import { policyLine } from './zoneframe.js';

const ROLES = ['global_master', 'domain_master', 'subdomain_master'];

// the scope of a grant in words: everything / a zone / a suffix of a zone (the dataset when there is more than one)
export function scopeNode(t, g) {
  if (g.role === 'global_master') return t('home.scope-all');
  return render([g.dataset, g.suffix ? `${g.suffix} (${g.zone})` : g.zone].filter(Boolean).join(' / '));
}

// grants: [{ id, principal_id, principal, role, dataset, zone, suffix, policy_id, policy, granted_by, granted_at }]
// o: { adminLinks: link the principal to its page, onDeleted(), who: show the principal column }
export function grantsTable(ctx, grants, o) {
  const { api, i18n, router } = ctx;
  const t = i18n.t;
  const err = message('error');
  const rows = grants.map((g) => h('tr', null,
    o.who === false ? null : h('th', { scope: 'row' }, o.adminLinks ? link(router.href('admin-principal', { id: String(g.principal_id) }), null, render(g.principal)) : render(g.principal)),
    h('td', null, ROLES.includes(g.role) ? t(`role.${g.role}`) : render(g.role)),
    h('td', null, scopeNode(t, g)),
    h('td', null, g.policy ? render(g.policy) : '-'),
    h('td', null, g.granted_at ? timeNode(g.granted_at, i18n.lang) : '-'),
    h('td', null, confirmButton({
      label: t('grants.delete'), confirmLabel: t('grants.delete-ask'), yes: t('common.yes'), no: t('common.no'),
      onConfirm: async () => {
        err.set(null);
        try {
          await api.del(`/grants/${g.id}`);
          ctx.announce(t('grants.deleted'));
          o.onDeleted();
        } catch (e) {
          err.setNodes(...problemNodes(i18n, e));
        }
      },
    }))));
  return h('div', { class: 'stack' },
    grants.length === 0 ? h('p', null, t('grants.none')) : h('table', { class: 'grants' }, h('caption', { class: 'sr-only' }, t('grants.caption')),
      h('thead', null, h('tr', null, o.who === false ? null : h('th', { scope: 'col' }, t('grants.h-principal')), ...['role', 'scope', 'policy', 'when', 'actions'].map((k) => h('th', { scope: 'col' }, t(`grants.h-${k}`))))),
      h('tbody', null, rows)),
    err.node);
}

// The form.  o:
//   policies      [policy of GET /rr-policies]
//   datasets      [{ name }] (the dataset field is shown when there is more than one and `dataset` is not given)
//   roles         the roles offered
//   principal     { id, name } when the grant is for a known principal (the field is not shown)
//   zone, dataset the zone (and dataset) when fixed (a zone's page)
//   own           the policy a grant must stay within (a domain master), or null
//   onDone()      after a grant was made
export function grantForm(ctx, o) {
  const { api, i18n } = ctx;
  const t = i18n.t;
  const usable = o.own ? o.policies.filter((p) => policyWithin(p, o.own)) : o.policies;
  const who = o.principal ? null : field({ label: t('grants.f-principal'), name: 'principal', required: true, maxlength: 255, spellcheck: false, autocapitalize: 'none', hint: t('grants.f-principal-hint') });
  const role = select({ label: t('grants.f-role'), name: 'role', options: o.roles.map((r) => ({ value: r, label: t(`role.${r}`) })), value: o.roles[o.roles.length > 1 ? 1 : 0] });
  const dataset = !o.dataset && o.datasets.length > 1 ? select({ label: t('grants.f-dataset'), name: 'dataset', options: o.datasets.map((d) => ({ value: d.name, label: d.name })), value: o.datasets[0].name }) : null;
  const zone = o.zone ? null : field({ label: t('grants.f-zone'), name: 'zone', maxlength: 255, spellcheck: false, autocapitalize: 'none', hint: t('grants.f-zone-hint') });
  const suffix = field({ label: t('grants.f-suffix'), name: 'suffix', maxlength: 255, spellcheck: false, autocapitalize: 'none', hint: t('grants.f-suffix-hint') });
  const policy = select({ label: t('grants.f-policy'), name: 'policy', options: usable.map((p) => ({ value: String(p.id), label: p.name })), value: usable.length ? String(usable[0].id) : '' });
  const policyHint = h('p', { class: 'hint' }, o.own ? t('grants.f-policy-own') : t('grants.f-policy-any'));
  const policyInfo = h('p', { class: 'hint' });
  const err = message('error');
  const ok = message('status');
  const submit = h('button', { type: 'submit', class: 'primary' }, t('grants.add'));
  const fields = h('div', { class: 'grid' }, who?.node, role.node, dataset?.node, zone?.node, suffix.node, policy.node);
  const form = h('form', { class: 'stack', novalidate: true }, fields, policyHint, policyInfo, err.node, ok.node, h('div', { class: 'actions' }, submit));

  function sync() {
    const r = role.input.value;
    suffix.node.hidden = r !== 'subdomain_master';
    if (zone) zone.node.hidden = r === 'global_master';
    if (dataset) dataset.node.hidden = r === 'global_master';
    const p = usable.find((x) => String(x.id) === policy.input.value);
    fill(policyInfo, p ? render(policyLine(t, p)) : null);
  }
  role.input.addEventListener('change', sync);
  policy.input.addEventListener('change', sync);
  sync();
  if (usable.length === 0) fill(policyInfo, t('grants.no-policy'));

  form.addEventListener('submit', (ev) => {
    ev.preventDefault();
    busy(submit, async () => {
      err.set(null);
      ok.set(null);
      for (const f of [who, zone, suffix]) f?.setError(null);
      const r = role.input.value;
      let target = o.principal ?? null;
      try {
        if (!target) {
          if (who.input.value.trim() === '') { who.setError(t('grants.need-principal')); who.focus(); return; }
          target = await lookupPrincipal(api, who.input.value);
          if (!target) { who.setError(t('grants.no-principal')); who.focus(); return; }
        }
        if (policy.input.value === '') { err.set(t('grants.no-policy')); return; }
        const body = { principal: target.id, role: r, policy: Number(policy.input.value) };
        if (r !== 'global_master') {
          const z = o.zone ?? zone.input.value.trim();
          if (z === '') { zone.setError(t('grants.need-zone')); zone.focus(); return; }
          body.zone = z;
          const d = o.dataset ?? dataset?.input.value;
          if (d) body.dataset = d;
        }
        if (r === 'subdomain_master') {
          if (suffix.input.value.trim() === '') { suffix.setError(t('grants.need-suffix')); suffix.focus(); return; }
          body.suffix = suffix.input.value.trim();
        }
        await api.post('/grants', body);
        ok.set(t('grants.added'));
        ctx.announce(t('grants.added'));
        o.onDone();
      } catch (e) {
        const map = { '/suffix': suffix };
        if (who) map['/principal'] = who;
        if (zone) map['/zone'] = zone;
        const loose = e.errors?.length ? placeOnFields(e.errors, map) : [];
        if (!e.errors?.length || loose.length) err.setNodes(...problemNodes(i18n, e));
      }
    });
  });
  return { node: form };
}
