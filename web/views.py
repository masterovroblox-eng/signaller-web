import json
import random
import string
from functools import wraps

from django.http import JsonResponse, HttpResponse
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone

from .models import Staff, Investigation, AuditLog, DiscordWebhook


import os


def _ensure_admin():
    try:
        from web.models import Staff
        if Staff.objects.filter(role='admin').exists():
            return
        username = os.environ.get('DJANGO_SUPERUSER_USERNAME', 'admin')
        password = os.environ.get('DJANGO_SUPERUSER_PASSWORD', 'ChangeMe123!')
        user = Staff(username=username, role='admin', must_change_password=True, is_staff=True, is_superuser=True)
        user.set_password(password)
        user.save()
    except Exception:
        pass


def _json(request):
    try:
        return json.loads(request.body.decode('utf-8') or '{}')
    except Exception:
        return {}


def _staff(request):
    if request.user.is_authenticated:
        return request.user
    return None


def _require_auth(request):
    u = _staff(request)
    if not u:
        return None, JsonResponse({'error': 'Unauthorized'}, status=401)
    if u.is_locked:
        logout(request)
        return None, JsonResponse({'error': 'Account locked'}, status=403)
    if u.must_change_password:
        return None, JsonResponse({'error': 'Password change required'}, status=403)
    return u, None


def _require_admin(request):
    u, err = _require_auth(request)
    if err:
        return None, err
    if u.role != 'admin':
        return None, JsonResponse({'error': 'Forbidden'}, status=403)
    return u, None


def _inv_to_dict(inv, user):
    d = {
        'id': inv.id,
        'title': inv.title,
        'reference_code': inv.reference_code,
        'incident_date': inv.incident_date.isoformat() if inv.incident_date else None,
        'location': inv.location,
        'involved_parties': inv.involved_parties,
        'description': inv.description,
        'outcome': inv.outcome,
        'findings': inv.findings,
        'recommendations': inv.recommendations,
        'status': inv.status,
        'opened_by': inv.opened_by,
        'closed_by': inv.closed_by,
        'created_at': inv.created_at.isoformat() if inv.created_at else None,
        'updated_at': inv.updated_at.isoformat() if inv.updated_at else None,
        'closed_at': inv.closed_at.isoformat() if inv.closed_at else None,
        'share_token': str(inv.share_token),
        'mitigating_circumstances': inv.mitigating_circumstances,
        'aggravating_circumstances': inv.aggravating_circumstances,
        'witness_statements': inv.witness_statements or [],
        'approving_signature': inv.approving_signature,
        'offender_rank': inv.offender_rank,
        'previous_history': inv.previous_history,
        'is_redacted': inv.is_redacted,
    }
    if user.role == 'admin':
        d['investigators'] = inv.investigators
    else:
        d['investigators'] = None
    return d


def _audit(user, action, target=None, detail=None):
    try:
        AuditLog.objects.create(performed_by=user, action=action, target=target, detail=detail)
    except Exception:
        pass


# ---------- Page views ----------

def index(request):
    if request.user.is_authenticated:
        u = request.user
        if u.is_locked or u.must_change_password:
            logout(request)
            return redirect('/login')
        return redirect('/investigations')
    return redirect('/login')


def login_view(request):
    return render(request, 'login.html')


def logout_view(request):
    logout(request)
    return redirect('/login')


def investigations_view(request):
    u = request.user
    if not u.is_authenticated:
        return redirect('/login')
    if u.is_locked or u.must_change_password:
        logout(request)
        return redirect('/login')
    return render(request, 'investigations.html')


def investigation_view(request, pk):
    u = request.user
    if not u.is_authenticated:
        return redirect('/login')
    if u.is_locked or u.must_change_password:
        logout(request)
        return redirect('/login')
    return render(request, 'investigation.html')


def admin_view(request):
    u = request.user
    if not u.is_authenticated:
        return redirect('/login')
    if u.is_locked or u.must_change_password:
        logout(request)
        return redirect('/login')
    if u.role != 'admin':
        return redirect('/login')
    return render(request, 'admin.html')


def privacy_view(request):
    return render(request, 'privacy.html')


def terms_view(request):
    return render(request, 'terms.html')


def not_found_view(request):
    return render(request, '404.html', status=404)


# ---------- API ----------

@csrf_exempt
def api_me(request):
    u = _staff(request)
    if not u:
        return JsonResponse({'authenticated': False})
    return JsonResponse({
        'authenticated': True,
        'username': u.username,
        'role': u.role,
        'must_change_password': u.must_change_password,
        'is_locked': u.is_locked,
    })


@csrf_exempt
def api_login(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    _ensure_admin()
    data = _json(request)
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''
    user = authenticate(request, username=username, password=password)
    if user is None:
        return JsonResponse({'error': 'Invalid username or password.'}, status=401)
    if user.is_locked:
        return JsonResponse({'error': 'Account is locked by administration.'}, status=403)
    login(request, user)
    return JsonResponse({
        'success': True,
        'username': user.username,
        'role': user.role,
        'must_change_password': user.must_change_password,
    })


@csrf_exempt
def api_set_password(request):
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    u, err = _require_auth(request)
    # allow even if must_change_password (bypass _require_auth restriction) by handling separately
    if request.user.is_authenticated:
        u = request.user
    else:
        return JsonResponse({'error': 'Unauthorized'}, status=401)
    if u.is_locked:
        return JsonResponse({'error': 'Account locked'}, status=403)
    data = _json(request)
    new_password = data.get('new_password') or ''
    if len(new_password) < 6:
        return JsonResponse({'error': 'Password must be at least 6 characters.'}, status=400)
    if new_password == 'Buses123!':
        return JsonResponse({'error': 'You cannot reuse the temporary password.'}, status=400)
    u.set_password(new_password)
    u.must_change_password = False
    u.save()
    # keep session
    from django.contrib.auth import update_session_auth_hash
    update_session_auth_hash(request, u)
    _audit(u, 'SET_PASSWORD', u.username)
    return JsonResponse({'success': True})


@csrf_exempt
def api_logout(request):
    if request.user.is_authenticated:
        _audit(request.user, 'LOGOUT', request.user.username)
    logout(request)
    return JsonResponse({'success': True})


@csrf_exempt
def api_investigations(request):
    u, err = _require_auth(request)
    if err:
        return err
    if request.method == 'GET':
        qs = Investigation.objects.all()
        if u.role != 'admin':
            qs = qs.filter(is_redacted=False)
        qs = qs.order_by('-created_at')
        data = [_inv_to_dict(inv, u) for inv in qs]
        return JsonResponse(data, safe=False)
    if request.method == 'POST':
        data = _json(request)
        title = (data.get('title') or '').strip()
        if not title:
            return JsonResponse({'error': 'Title is required.'}, status=400)
        inv = Investigation(
            title=title,
            incident_date=data.get('incident_date') or None,
            location=(data.get('location') or '').strip() or None,
            involved_parties=(data.get('involved_parties') or '').strip() or None,
            description=(data.get('description') or '').strip() or None,
            outcome=(data.get('outcome') or '').strip() or None,
            mitigating_circumstances=(data.get('mitigating') or '').strip() or None,
            aggravating_circumstances=(data.get('aggravating') or '').strip() or None,
            witness_statements=data.get('witness') or [],
            approving_signature=data.get('signature'),
            offender_rank=(data.get('rank') or '').strip() or None,
            previous_history=(data.get('history') or '').strip() or None,
            opened_by=u.username,
        )
        if u.role == 'admin':
            inv.investigators = (data.get('investigators') or '').strip() or None
            inv.is_redacted = bool(data.get('redacted'))
        inv.save()
        _audit(u, 'CREATE_INVESTIGATION', inv.title)
        return JsonResponse({'success': True, 'id': inv.id})
    return JsonResponse({'error': 'Method not allowed'}, status=405)


@csrf_exempt
def api_investigation(request, pk):
    u, err = _require_auth(request)
    if err:
        return err
    try:
        inv = Investigation.objects.get(pk=pk)
    except Investigation.DoesNotExist:
        return JsonResponse({'error': 'Not found'}, status=404)
    if inv.is_redacted and u.role != 'admin':
        return JsonResponse({'error': 'Forbidden: redacted'}, status=403)
    if request.method == 'GET':
        return JsonResponse(_inv_to_dict(inv, u))
    if request.method == 'POST':
        data = _json(request)
        # redacted restriction
        if inv.is_redacted and u.role != 'admin':
            return JsonResponse({'error': 'Forbidden'}, status=403)
        if u.role != 'admin' and (data.get('investigators') is not None or data.get('redacted') is not None):
            return JsonResponse({'error': 'Forbidden: only admin'}, status=403)
        if 'title' in data:
            inv.title = (data.get('title') or '').strip() or inv.title
        if 'incident_date' in data:
            inv.incident_date = data.get('incident_date') or None
        if 'location' in data:
            inv.location = (data.get('location') or '').strip() or None
        if 'involved_parties' in data:
            inv.involved_parties = (data.get('involved_parties') or '').strip() or None
        if 'description' in data:
            inv.description = (data.get('description') or '').strip() or None
        if 'outcome' in data:
            inv.outcome = (data.get('outcome') or '').strip() or None
        if 'findings' in data:
            inv.findings = (data.get('findings') or '').strip() or None
        if 'recommendations' in data:
            inv.recommendations = (data.get('recommendations') or '').strip() or None
        if 'mitigating' in data:
            inv.mitigating_circumstances = (data.get('mitigating') or '').strip() or None
        if 'aggravating' in data:
            inv.aggravating_circumstances = (data.get('aggravating') or '').strip() or None
        if 'witness' in data:
            inv.witness_statements = data.get('witness') or inv.witness_statements
        if 'signature' in data:
            inv.approving_signature = data.get('signature')
        if 'rank' in data:
            inv.offender_rank = (data.get('rank') or '').strip() or None
        if 'history' in data:
            inv.previous_history = (data.get('history') or '').strip() or None
        if u.role == 'admin':
            if 'investigators' in data:
                inv.investigators = (data.get('investigators') or '').strip() or None
            if 'redacted' in data:
                inv.is_redacted = bool(data.get('redacted'))
        inv.updated_at = timezone.now()
        inv.save()
        _audit(u, 'UPDATE_INVESTIGATION', inv.title)
        return JsonResponse({'success': True})
    return JsonResponse({'error': 'Method not allowed'}, status=405)


@csrf_exempt
def api_close_investigation(request, pk):
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    u, err = _require_auth(request)
    if err:
        return err
    try:
        inv = Investigation.objects.get(pk=pk)
    except Investigation.DoesNotExist:
        return JsonResponse({'error': 'Not found'}, status=404)
    if inv.is_redacted and u.role != 'admin':
        return JsonResponse({'error': 'Forbidden'}, status=403)
    inv.status = 'closed'
    inv.closed_by = u.username
    inv.closed_at = timezone.now()
    inv.updated_at = timezone.now()
    inv.save()
    _audit(u, 'CLOSE_INVESTIGATION', inv.title)
    return JsonResponse({'success': True})


@csrf_exempt
def api_reopen_investigation(request, pk):
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    u, err = _require_auth(request)
    if err:
        return err
    try:
        inv = Investigation.objects.get(pk=pk)
    except Investigation.DoesNotExist:
        return JsonResponse({'error': 'Not found'}, status=404)
    if inv.is_redacted and u.role != 'admin':
        return JsonResponse({'error': 'Forbidden'}, status=403)
    inv.status = 'open'
    inv.closed_by = None
    inv.closed_at = None
    inv.updated_at = timezone.now()
    inv.save()
    _audit(u, 'REOPEN_INVESTIGATION', inv.title)
    return JsonResponse({'success': True})


@csrf_exempt
def api_admin_staff(request):
    u, err = _require_admin(request)
    if err:
        return err
    if request.method == 'GET':
        staff = Staff.objects.all().order_by('username')
        data = []
        for s in staff:
            data.append({
                'username': s.username,
                'role': s.role,
                'must_change_password': s.must_change_password,
                'on_loa': s.on_loa,
                'is_locked': s.is_locked,
                'locked_by': s.locked_by,
                'locked_at': s.locked_at.isoformat() if s.locked_at else None,
                'roblox_username': s.roblox_username,
                'discord_username': s.discord_username,
                'contact_info': s.contact_info,
                'admin_notes': s.admin_notes,
                'joined_at': s.joined_at.isoformat() if s.joined_at else None,
            })
        return JsonResponse(data, safe=False)
    if request.method == 'POST':
        data = _json(request)
        username = (data.get('username') or '').strip()
        if not username:
            return JsonResponse({'error': 'Enter username'}, status=400)
        if Staff.objects.filter(username=username).exists():
            return JsonResponse({'error': 'Username already exists.'}, status=400)
        temp = ''.join(random.choices(string.digits, k=5))
        new_user = Staff(username=username, role='staff', must_change_password=True)
        new_user.set_password(temp)
        new_user.save()
        _audit(u, 'ADD_STAFF', username, 'Account created')
        return JsonResponse({'out_username': username, 'out_temp_password': temp})
    return JsonResponse({'error': 'Method not allowed'}, status=405)


@csrf_exempt
def api_admin_staff_detail(request, username):
    u, err = _require_admin(request)
    if err:
        return err
    try:
        target = Staff.objects.get(username=username)
    except Staff.DoesNotExist:
        return JsonResponse({'error': 'Not found'}, status=404)
    if request.method == 'DELETE':
        if target.is_owner and u.username != target.username:
            return JsonResponse({'error': 'Cannot delete owner'}, status=403)
        target.delete()
        _audit(u, 'DELETE_STAFF', username)
        return JsonResponse({'success': True})
    if request.method == 'PATCH':
        data = _json(request)
        if 'new_username' in data:
            newu = (data.get('new_username') or '').strip()
            if not newu:
                return JsonResponse({'error': 'Enter new username'}, status=400)
            if Staff.objects.filter(username=newu).exists():
                return JsonResponse({'error': 'Username already exists.'}, status=400)
            # rename
            old = target.username
            target.username = newu
            target.save()
            # update investigations opened_by? not required but nice
            Investigation.objects.filter(opened_by=old).update(opened_by=newu)
            Investigation.objects.filter(closed_by=old).update(closed_by=newu)
            _audit(u, 'RENAME_STAFF', old, 'Renamed to ' + newu)
            return JsonResponse({'success': True})
        if 'on_loa' in data:
            target.on_loa = bool(data.get('on_loa'))
            target.save()
            _audit(u, 'SET_LOA', username)
            return JsonResponse({'success': True})
        if 'profile' in data:
            p = data.get('profile') or {}
            target.roblox_username = p.get('roblox_username') or target.roblox_username
            target.discord_username = p.get('discord_username') or target.discord_username
            target.contact_info = p.get('contact_info') or target.contact_info
            target.admin_notes = p.get('admin_notes') or target.admin_notes
            target.joined_at = p.get('joined_at') or target.joined_at
            target.save()
            _audit(u, 'UPDATE_PROFILE', username)
            return JsonResponse({'success': True})
        return JsonResponse({'error': 'Nothing to update'}, status=400)
    return JsonResponse({'error': 'Method not allowed'}, status=405)


@csrf_exempt
def api_admin_reset_password(request, username):
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    u, err = _require_admin(request)
    if err:
        return err
    try:
        target = Staff.objects.get(username=username)
    except Staff.DoesNotExist:
        return JsonResponse({'error': 'Not found'}, status=404)
    temp = ''.join(random.choices(string.digits, k=5))
    target.set_password(temp)
    target.must_change_password = True
    target.save()
    _audit(u, 'RESET_PASSWORD', username)
    return JsonResponse({'out_username': username, 'out_temp_password': temp})


@csrf_exempt
def api_admin_lock(request, username):
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    u, err = _require_admin(request)
    if err:
        return err
    # owner only
    first_admin = Staff.objects.filter(role='admin').order_by('created_at').first()
    if not first_admin or first_admin.username != u.username:
        return JsonResponse({'error': f'Only the system owner ({first_admin.username if first_admin else "unknown"}) can lock accounts'}, status=403)
    try:
        target = Staff.objects.get(username=username)
    except Staff.DoesNotExist:
        return JsonResponse({'error': 'Not found'}, status=404)
    if target.username == u.username:
        return JsonResponse({'error': 'Cannot lock the owner account'}, status=403)
    data = _json(request)
    should_lock = bool(data.get('locked', True))
    target.is_locked = should_lock
    target.locked_by = u.username if should_lock else None
    target.locked_at = timezone.now() if should_lock else None
    target.save()
    _audit(u, 'LOCK_ACCOUNT' if should_lock else 'UNLOCK_ACCOUNT', username)
    return JsonResponse({'success': True})


@csrf_exempt
def api_admin_rename(request, username):
    # alias handled by detail PATCH; keep endpoint for frontend
    if request.method != 'POST':
        return JsonResponse({'error': 'Method not allowed'}, status=405)
    u, err = _require_admin(request)
    if err:
        return err
    data = _json(request)
    new_username = (data.get('new_username') or '').strip()
    if not new_username:
        return JsonResponse({'error': 'Enter new username'}, status=400)
    try:
        target = Staff.objects.get(username=username)
    except Staff.DoesNotExist:
        return JsonResponse({'error': 'Not found'}, status=404)
    if Staff.objects.filter(username=new_username).exists():
        return JsonResponse({'error': 'Username already exists.'}, status=400)
    old = target.username
    target.username = new_username
    target.save()
    Investigation.objects.filter(opened_by=old).update(opened_by=new_username)
    Investigation.objects.filter(closed_by=old).update(closed_by=new_username)
    _audit(u, 'RENAME_STAFF', old, 'Renamed to ' + new_username)
    return JsonResponse({'success': True})