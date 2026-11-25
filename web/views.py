import json
import random
import string
from functools import wraps

from django.http import JsonResponse, HttpResponse
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.views.decorators.csrf import csrf_exempt
from django.utils import timezone

from .models import Staff, Investigation, AuditLog, DiscordWebhook, WriteUp, SignallerSupervisorLimit

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

def reset_admin_view(request):
    import os
    token = request.GET.get('token', '')
    expected = os.environ.get('ADMIN_RESET_TOKEN', 'reset-admin-now')
    if token != expected:
        from django.http import HttpResponseForbidden
        return HttpResponseForbidden('Invalid or missing token.')
    _ensure_admin()
    from web.models import Staff
    username = os.environ.get('DJANGO_SUPERUSER_USERNAME', 'admin')
    password = os.environ.get('DJANGO_SUPERUSER_PASSWORD', 'ChangeMe123!')
    try:
        user = Staff.objects.get(username=username)
    except Staff.DoesNotExist:
        return HttpResponse('Admin account not found; check DJANGO_SUPERUSER_USERNAME.')
    user.set_password(password)
    user.must_change_password = True
    user.save()
    return HttpResponse(f'Admin "{username}" password reset. Log in with the bootstrap password, then set a permanent one.')


def index(request):
    if request.user.is_authenticated:
        u = request.user
        if u.is_locked or u.must_change_password:
            logout(request)
            return redirect('/login')
        return redirect('/home')
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


# -------------------------------------------------
#  NEW VIEWS (appended below the existing API views)
# -------------------------------------------------
from django.contrib import messages
from django.core.files.base import ContentFile
from django.core import signing
from django.template.loader import render_to_string
from django.http import Http404, HttpResponseBadRequest
from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas as pdf_canvas


# -----------------------------------------------------------------
#  Home page – role‑aware start screen (requires login)
# -----------------------------------------------------------------
def home_view(request):
    """
    Shows a start page after login.
    - staff / controller -> "Choose your next step" with buttons to
      Investigations, Write‑ups, Supervisor view, etc.
    - admin            -> direct to the admin dashboard.
    """
    if not request.user.is_authenticated:
        return redirect('/login')
    u = request.user
    if u.is_locked or u.must_change_password:
        logout(request)
        return redirect('/login')
    # role based routing
    if u.role == 'admin':
        return redirect('/admin-dashboard/')
    # staff / controller see a simple start page
    return render(request, 'home.html', {'user': u})


# -----------------------------------------------------------------
#  Supervisor page – see signallers, their write‑ups, add a signaller (1/hr)
# -----------------------------------------------------------------
def supervisor_view(request):
    u, err = _require_auth(request)
    if err:
        return redirect('/login')
    if u.role not in ('staff', 'admin'):
        return redirect('/login')

    # ---- list signallers that this supervisor has assigned ----
    limits = SignallerSupervisorLimit.objects.filter(
        supervisor=u).order_by('-assigned_at')[:20]
    # group by signaller – show how many active (within the hour)
    signaller_counts = {}
    for l in limits:
        signaller_counts[l.signaller] = signaller_counts.get(l.signaller, 0) + 1

    # ---- write‑ups that mention this supervisor (or his signallers) ----
    write_ups = WriteUp.objects.filter(
        status='approved').select_related('investigation')

    # ---- handle adding a new signaller (POST) ----
    if request.method == 'POST':
        sig_username = request.POST.get('signaller_username', '').strip()
        if not sig_username:
            messages.error(request, 'Enter a signaller username.')
        elif SignallerSupervisorLimit.objects.filter(
                supervisor=u, signaller=sig_username).exists():
            # already has one within the hour – block
            messages.error(request, 'You already have a signaller assigned this hour.')
        else:
            try:
                SignallerSupervisorLimit.objects.create(
                    supervisor=u, signaller=sig_username)
                messages.success(request, 'Signaller added (valid for this hour).')
            except ValueError:
                messages.error(request, 'A supervisor may have at most 1 signaller per hour.')
        return redirect('supervisor')

    return render(request, 'supervisor.html', {
        'user': u,
        'signaller_counts': signaller_counts,
        'write_ups': write_ups,
    })


# -----------------------------------------------------------------
#  Administrator dashboard – audit log, member list, add signaller/supervisor
# -----------------------------------------------------------------
def admin_dashboard_view(request):
    u, err = _require_admin(request)
    if err:
        return redirect('/login')

    # ----- audit log -------------------------------------------------
    audit_entries = AuditLog.objects.order_by('-created_at')[:50]

    # ----- member list -------------------------------------------------
    members = Staff.objects.all().order_by('username')

    # ----- add signaller / supervisor (admin only) -----------------
    if request.method == 'POST':
        form_type = request.POST.get('form_type')
        username = request.POST.get('username', '').strip()
        role = request.POST.get('role')
        if not username:
            messages.error(request, 'Username required.')
        elif Staff.objects.filter(username=username).exists():
            messages.error(request, 'Username already exists.')
        else:
            temp = ''.join(random.choices('0123456789', k=5))
            new_user = Staff(username=username,
                             role=role,
                             must_change_password=True)
            new_user.set_password(temp)
            new_user.save()
            # audit
            AuditLog.objects.create(
                performed_by=u.username,
                action='ADD_STAFF',
                target=username,
                detail=f'Role={role}, temp PW={temp}')
            messages.success(request, f'User {username} created (temp password: {temp}).')
            return redirect('admin_dashboard')

    return render(request, 'admin_dashboard.html', {
        'user': u,
        'audit_entries': audit_entries,
        'members': members,
    })


# -----------------------------------------------------------------
#  Write‑up creation (supervisor) -------------------------------------------------
# -----------------------------------------------------------------
def writeup_create(request):
    u, err = _require_auth(request)
    if err:
        return redirect('/login')
    if u.role not in ('staff', 'admin'):        # only supervisors can request
        return redirect('/login')

    if request.method == 'POST':
        signaller = request.POST.get('signaller', '').strip()
        reason = request.POST.get('reason', '').strip()
        evidence = request.POST.get('evidence', '').strip()   # free‑form text/links
        if not signaller or not reason:
            messages.error(request, 'Title and description are required.')
        else:
            WriteUp.objects.create(
                signaller=signaller,
                reason=reason,
                evidence=evidence,
                status='pending',
                created_by=u)           # we store the creator on the model later
            messages.success(request, 'Write‑up submitted – pending manager approval.')
            return redirect('home')

    return render(request, 'writeup_form.html', {'user': u})


# -----------------------------------------------------------------
#  Write‑up approval (manager) -------------------------------------------------
# -----------------------------------------------------------------
def writeup_approve(request, pk):
    u, err = _require_admin(request)          # only admins may approve
    if err:
        return redirect('/login')

    from django.shortcuts import get_object_or_404
    wu = get_object_or_404(WriteUp, pk=pk)
    if request.method == 'POST':
        action = request.POST.get('action')      # 'approve' or 'reject'
        if action == 'approve':
            wu.status = 'approved'
            wu.approved_at = timezone.now()
            wu.approved_by = u
            wu.save()
            # optional: notify the signaller (here we just add a message)
            messages.success(request, f'Write‑up #{wu.id} approved – the signaller can now see it on their account.')
        else:
            wu.status = 'rejected'
            wu.save()
            messages.success(request, f'Write‑up #{wu.id} rejected.')
        return redirect('home')   # or a dedicated write‑up list

    # GET – show confirmation page
    return render(request, 'writeup_confirm.html', {'writeup': wu, 'user': u})


# -----------------------------------------------------------------
#  Write-up PDF download
# -----------------------------------------------------------------
def writeup_pdf(request, pk):
    u, err = _require_auth(request)
    if err:
        return redirect('/login')

    from django.shortcuts import get_object_or_404
    wu = get_object_or_404(WriteUp, pk=pk)

    # Only approved write-ups can be downloaded as PDF, and only by the signaller, supervisor, or admin
    if wu.status != 'approved':
        messages.error(request, 'Write-up must be approved before downloading.')
        return redirect('home')

    # Permission: signaller, creator (supervisor), or admin
    is_signaller = (u.username == wu.signaller)
    is_creator = (wu.created_by and u.username == wu.created_by.username)
    is_admin = u.is_admin
    if not (is_signaller or is_creator or is_admin):
        messages.error(request, 'You do not have permission to download this write-up.')
        return redirect('home')

    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas as pdf_canvas
    from django.http import HttpResponse

    buffer = BytesIO()
    p = pdf_canvas.Canvas(buffer, pagesize=A4)
    width, height = A4

    # Title
    p.setFont('Helvetica-Bold', 16)
    p.drawString(50, height - 50, 'Write-up Report')
    p.setFont('Helvetica', 10)
    p.drawString(50, height - 70, f'Generated: {timezone.now().strftime("%d %B %Y %H:%M")}')

    # Write-up details
    y = height - 110
    p.setFont('Helvetica-Bold', 12)
    p.drawString(50, y, 'Write-up Details')
    y -= 20
    p.setFont('Helvetica', 11)
    details = [
        ('ID', str(wu.id)),
        ('Signaller', wu.signaller),
        ('Status', wu.status.title()),
        ('Created', wu.created_at.strftime('%d %B %Y %H:%M') if wu.created_at else 'N/A'),
        ('Approved', wu.approved_at.strftime('%d %B %Y %H:%M') if wu.approved_at else 'N/A'),
        ('Approved By', wu.approved_by.username if wu.approved_by else 'N/A'),
    ]
    for label, value in details:
        p.drawString(50, y, f'{label}: {value}')
        y -= 18

    # Reason
    y -= 10
    p.setFont('Helvetica-Bold', 12)
    p.drawString(50, y, 'Reason / Incident Description')
    y -= 20
    p.setFont('Helvetica', 11)
    for line in wu.reason.split('\n'):
        p.drawString(50, y, line[:100])
        y -= 16
        if y < 50:
            p.showPage()
            y = height - 50

    # Evidence
    if wu.evidence:
        y -= 10
        p.setFont('Helvetica-Bold', 12)
        p.drawString(50, y, 'Evidence')
        y -= 20
        p.setFont('Helvetica', 11)
        for line in wu.evidence.split('\n'):
            p.drawString(50, y, line[:100])
            y -= 16
            if y < 50:
                p.showPage()
                y = height - 50

    # Linked investigation
    if wu.investigation:
        y -= 10
        p.setFont('Helvetica-Bold', 12)
        p.drawString(50, y, 'Linked Investigation')
        y -= 20
        p.setFont('Helvetica', 11)
        p.drawString(50, y, f'Title: {wu.investigation.title}')
        y -= 16
        p.drawString(50, y, f'Reference: {wu.investigation.reference_code}')
        y -= 16
        p.drawString(50, y, f'Status: {wu.investigation.status}')

    p.showPage()
    p.save()

    buffer.seek(0)
    response = HttpResponse(buffer, content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="writeup_{wu.id}.pdf"'
    return response


# -----------------------------------------------------------------
#  Investigation edit – now uses the fresh CSS (style.css) -------------
# -----------------------------------------------------------------
def investigation_edit(request, pk):
    """Allow editing an investigation with the fresh Signaller‑Web CSS."""
    u, err = _require_auth(request)
    if err:
        return redirect('/login')

    from django.shortcuts import get_object_or_404
    inv = get_object_or_404(Investigation, pk=pk)

    # Simple permission check – only the opener or an admin may edit
    if u != inv.opened_by and not u.is_admin:
        messages.error(request, 'You are not allowed to edit this investigation.')
        return redirect('investigation', pk=inv.pk)

    if request.method == 'POST':
        # basic field updates – you can expand this form as needed
        inv.title = request.POST.get('title', inv.title) or inv.title
        inv.location = request.POST.get('location', inv.location) or inv.location
        inv.description = request.POST.get('description', inv.description) or inv.description
        inv.outcome = request.POST.get('outcome', inv.outcome) or inv.outcome
        inv.findings = request.POST.get('findings', inv.findings) or inv.findings
        inv.recommendations = request.POST.get('recommendations', inv.recommendations) or inv.recommendations
        inv.save()
        messages.success(request, 'Investigation updated.')
        return redirect('investigation', pk=inv.pk)

    # GET – render the edit form (the template already pulls in style.css)
    return render(request, 'investigation_edit.html', {
        'user': u,
        'inv': inv,
    })