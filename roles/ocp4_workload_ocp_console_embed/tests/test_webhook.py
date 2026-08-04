import unittest
import json
import base64
import threading
from unittest.mock import patch, MagicMock, mock_open
import sys
import os
import io

sys.path.append(os.path.join(os.path.dirname(__file__), '../files'))

import webhook


def _mock_context_manager(obj):
    """Make *obj* usable as a context manager."""
    obj.__enter__ = MagicMock(return_value=obj)
    obj.__exit__ = MagicMock(return_value=False)
    return obj


class TestWebhookAdmission(unittest.TestCase):

    def setUp(self):
        self.handler = webhook.Handler.__new__(webhook.Handler)
        self.handler.allow = MagicMock(side_effect=lambda uid: {'response': {'uid': uid, 'allowed': True}})

    def test_handle_review_wrong_route(self):
        body = {
            'request': {
                'uid': '123',
                'object': {
                    'metadata': {'name': 'other-route', 'namespace': 'openshift-authentication'},
                    'spec': {'tls': {'termination': 'passthrough'}}
                }
            }
        }
        webhook.SERVICE_CA = "fake-ca"
        self.handler.handle_review(body, '123')
        self.handler.allow.assert_called_with('123')

    def test_handle_review_wrong_namespace(self):
        body = {
            'request': {
                'uid': '123',
                'object': {
                    'metadata': {'name': 'oauth-openshift', 'namespace': 'other-namespace'},
                    'spec': {'tls': {'termination': 'passthrough'}}
                }
            }
        }
        webhook.SERVICE_CA = "fake-ca"
        self.handler.handle_review(body, '123')
        self.handler.allow.assert_called_with('123')

    def test_handle_review_not_passthrough(self):
        body = {
            'request': {
                'uid': '123',
                'object': {
                    'metadata': {'name': 'oauth-openshift', 'namespace': 'openshift-authentication'},
                    'spec': {'tls': {'termination': 'reencrypt'}}
                }
            }
        }
        webhook.SERVICE_CA = "fake-ca"
        self.handler.handle_review(body, '123')
        self.handler.allow.assert_called_with('123')

    def test_handle_review_no_service_ca(self):
        body = {
            'request': {
                'uid': '123',
                'object': {
                    'metadata': {'name': 'oauth-openshift', 'namespace': 'openshift-authentication'},
                    'spec': {'tls': {'termination': 'passthrough'}}
                }
            }
        }
        webhook.SERVICE_CA = None
        self.handler.handle_review(body, '123')
        self.handler.allow.assert_called_with('123')

    def test_handle_review_success(self):
        body = {
            'request': {
                'uid': '123',
                'object': {
                    'metadata': {'name': 'oauth-openshift', 'namespace': 'openshift-authentication'},
                    'spec': {'tls': {'termination': 'passthrough'}}
                }
            }
        }
        webhook.SERVICE_CA = "fake-ca-content"

        resp = self.handler.handle_review(body, '123')

        self.assertEqual(resp['kind'], 'AdmissionReview')
        self.assertTrue(resp['response']['allowed'])
        self.assertEqual(resp['response']['patchType'], 'JSONPatch')

        patch_json = base64.b64decode(resp['response']['patch']).decode()
        patches = json.loads(patch_json)

        self.assertEqual(len(patches), 3)
        self.assertEqual(patches[0]['value'], 'reencrypt')
        self.assertEqual(patches[2]['value'], 'fake-ca-content')


class TestReconcileRoute(unittest.TestCase):
    """Integration-style tests checking behavior via _reconcile_once()."""

    def test_skips_when_no_service_ca(self):
        webhook.SERVICE_CA = None
        with patch.object(webhook, '_load_sa_token') as mock_token:
            webhook._reconcile_once()
            mock_token.assert_not_called()

    def test_skips_when_no_sa_token(self):
        webhook.SERVICE_CA = "fake-ca"
        with patch.object(webhook, '_load_sa_token', return_value=None):
            webhook._reconcile_once()

    @patch('webhook.urllib.request.urlopen')
    @patch.object(webhook, '_kube_ssl_context')
    @patch.object(webhook, '_load_sa_token', return_value='fake-token')
    def test_skips_when_already_reencrypt(self, _tok, _ctx, mock_urlopen):
        webhook.SERVICE_CA = "fake-ca"
        route_json = json.dumps({
            'spec': {'tls': {'termination': 'reencrypt'}}
        }).encode()
        mock_resp = MagicMock()
        mock_resp.read.return_value = route_json
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        webhook._reconcile_once()

        mock_urlopen.assert_called_once()

    @patch('webhook.urllib.request.urlopen')
    @patch.object(webhook, '_kube_ssl_context')
    @patch.object(webhook, '_load_sa_token', return_value='fake-token')
    def test_patches_when_passthrough(self, _tok, _ctx, mock_urlopen):
        webhook.SERVICE_CA = "fake-ca"
        route_json = json.dumps({
            'spec': {'tls': {'termination': 'passthrough'}}
        }).encode()

        get_resp = MagicMock()
        get_resp.read.return_value = route_json
        get_resp.__enter__ = MagicMock(return_value=get_resp)
        get_resp.__exit__ = MagicMock(return_value=False)

        patch_resp = MagicMock()
        patch_resp.read.return_value = b'{}'
        patch_resp.__enter__ = MagicMock(return_value=patch_resp)
        patch_resp.__exit__ = MagicMock(return_value=False)

        mock_urlopen.side_effect = [get_resp, patch_resp]

        webhook._reconcile_once()

        self.assertEqual(mock_urlopen.call_count, 2)
        patch_call = mock_urlopen.call_args_list[1]
        req = patch_call[0][0]
        self.assertEqual(req.get_method(), 'PATCH')
        self.assertEqual(req.get_header('Content-type'), 'application/merge-patch+json')
        body = json.loads(req.data.decode())
        self.assertEqual(body['spec']['tls']['termination'], 'reencrypt')
        self.assertEqual(body['spec']['tls']['destinationCACertificate'], 'fake-ca')

    @patch('webhook.urllib.request.urlopen')
    @patch.object(webhook, '_kube_ssl_context')
    @patch.object(webhook, '_load_sa_token', return_value='fake-token')
    def test_handles_get_failure_gracefully(self, _tok, _ctx, mock_urlopen):
        webhook.SERVICE_CA = "fake-ca"
        mock_urlopen.side_effect = urllib_error_stub()

        webhook._reconcile_once()
        mock_urlopen.assert_called_once()


class TestReconcileOnce(unittest.TestCase):
    """Tests for _reconcile_once() return values."""

    def test_returns_retry_when_no_service_ca(self):
        webhook.SERVICE_CA = None
        self.assertEqual(webhook._reconcile_once(), 'retry')

    def test_returns_retry_when_no_sa_token(self):
        webhook.SERVICE_CA = "fake-ca"
        with patch.object(webhook, '_load_sa_token', return_value=None):
            self.assertEqual(webhook._reconcile_once(), 'retry')

    @patch('webhook.urllib.request.urlopen')
    @patch.object(webhook, '_kube_ssl_context')
    @patch.object(webhook, '_load_sa_token', return_value='fake-token')
    def test_returns_ok_when_already_reencrypt(self, _tok, _ctx, mock_urlopen):
        webhook.SERVICE_CA = "fake-ca"
        route_json = json.dumps({
            'spec': {'tls': {'termination': 'reencrypt'}}
        }).encode()
        mock_resp = MagicMock()
        mock_resp.read.return_value = route_json
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        self.assertEqual(webhook._reconcile_once(), 'ok')

    @patch('webhook.urllib.request.urlopen')
    @patch.object(webhook, '_kube_ssl_context')
    @patch.object(webhook, '_load_sa_token', return_value='fake-token')
    def test_returns_patched_after_fixing(self, _tok, _ctx, mock_urlopen):
        webhook.SERVICE_CA = "fake-ca"
        route_json = json.dumps({
            'spec': {'tls': {'termination': 'passthrough'}}
        }).encode()

        get_resp = MagicMock()
        get_resp.read.return_value = route_json
        get_resp.__enter__ = MagicMock(return_value=get_resp)
        get_resp.__exit__ = MagicMock(return_value=False)

        patch_resp = MagicMock()
        patch_resp.read.return_value = b'{}'
        patch_resp.__enter__ = MagicMock(return_value=patch_resp)
        patch_resp.__exit__ = MagicMock(return_value=False)

        mock_urlopen.side_effect = [get_resp, patch_resp]

        self.assertEqual(webhook._reconcile_once(), 'patched')

    @patch('webhook.urllib.request.urlopen')
    @patch.object(webhook, '_kube_ssl_context')
    @patch.object(webhook, '_load_sa_token', return_value='fake-token')
    def test_returns_retry_on_get_failure(self, _tok, _ctx, mock_urlopen):
        webhook.SERVICE_CA = "fake-ca"
        mock_urlopen.side_effect = urllib_error_stub()

        self.assertEqual(webhook._reconcile_once(), 'retry')

    @patch('webhook.urllib.request.urlopen')
    @patch.object(webhook, '_kube_ssl_context')
    @patch.object(webhook, '_load_sa_token', return_value='fake-token')
    def test_returns_retry_on_patch_failure(self, _tok, _ctx, mock_urlopen):
        webhook.SERVICE_CA = "fake-ca"
        route_json = json.dumps({
            'spec': {'tls': {'termination': 'passthrough'}}
        }).encode()

        get_resp = MagicMock()
        get_resp.read.return_value = route_json
        get_resp.__enter__ = MagicMock(return_value=get_resp)
        get_resp.__exit__ = MagicMock(return_value=False)

        mock_urlopen.side_effect = [get_resp, urllib_error_stub()]

        self.assertEqual(webhook._reconcile_once(), 'retry')


class TestPatchToReencrypt(unittest.TestCase):
    """Tests for the extracted _patch_to_reencrypt() helper."""

    @patch('webhook.urllib.request.urlopen')
    @patch.object(webhook, '_kube_ssl_context')
    def test_sends_merge_patch(self, _ctx, mock_urlopen):
        webhook.SERVICE_CA = "fake-ca"
        resp = _mock_context_manager(MagicMock())
        resp.read.return_value = b'{}'
        mock_urlopen.return_value = resp

        webhook._patch_to_reencrypt('tok', _ctx)

        req = mock_urlopen.call_args[0][0]
        self.assertEqual(req.get_method(), 'PATCH')
        self.assertEqual(req.get_header('Content-type'),
                         'application/merge-patch+json')
        body = json.loads(req.data.decode())
        self.assertEqual(body['spec']['tls']['termination'], 'reencrypt')
        self.assertEqual(body['spec']['tls']['destinationCACertificate'],
                         'fake-ca')


class TestWatchRoute(unittest.TestCase):
    """Tests for _watch_route() — the Kubernetes watch loop."""

    def _route_json(self, termination='reencrypt', rv='100'):
        return json.dumps({
            'metadata': {'resourceVersion': rv},
            'spec': {'tls': {'termination': termination}},
        }).encode()

    def _event_line(self, event_type, termination='reencrypt', code=None):
        obj = {'spec': {'tls': {'termination': termination}}}
        if code is not None:
            obj = {'code': code, 'message': 'Gone'}
        return json.dumps({'type': event_type, 'object': obj}).encode() + b'\n'

    @patch('webhook.urllib.request.urlopen')
    @patch.object(webhook, '_kube_ssl_context')
    @patch.object(webhook, '_load_sa_token', return_value='fake-token')
    def test_modified_passthrough_triggers_patch(self, _tok, _ctx, mock_urlopen):
        webhook.SERVICE_CA = "fake-ca"
        stop = threading.Event()

        get_resp = _mock_context_manager(MagicMock())
        get_resp.read.return_value = self._route_json('reencrypt', '42')

        watch_resp = _mock_context_manager(MagicMock())
        watch_resp.__iter__ = MagicMock(return_value=iter([
            self._event_line('MODIFIED', 'passthrough'),
        ]))

        patch_resp = _mock_context_manager(MagicMock())
        patch_resp.read.return_value = b'{}'

        mock_urlopen.side_effect = [get_resp, watch_resp, patch_resp]

        webhook._watch_route(stop)

        self.assertEqual(mock_urlopen.call_count, 3)
        patch_req = mock_urlopen.call_args_list[2][0][0]
        self.assertEqual(patch_req.get_method(), 'PATCH')

    @patch('webhook.urllib.request.urlopen')
    @patch.object(webhook, '_kube_ssl_context')
    @patch.object(webhook, '_load_sa_token', return_value='fake-token')
    def test_modified_reencrypt_no_patch(self, _tok, _ctx, mock_urlopen):
        webhook.SERVICE_CA = "fake-ca"
        stop = threading.Event()

        get_resp = _mock_context_manager(MagicMock())
        get_resp.read.return_value = self._route_json('reencrypt', '42')

        watch_resp = _mock_context_manager(MagicMock())
        watch_resp.__iter__ = MagicMock(return_value=iter([
            self._event_line('MODIFIED', 'reencrypt'),
        ]))

        mock_urlopen.side_effect = [get_resp, watch_resp]

        webhook._watch_route(stop)

        self.assertEqual(mock_urlopen.call_count, 2)

    @patch('webhook.urllib.request.urlopen')
    @patch.object(webhook, '_kube_ssl_context')
    @patch.object(webhook, '_load_sa_token', return_value='fake-token')
    def test_bookmark_ignored(self, _tok, _ctx, mock_urlopen):
        webhook.SERVICE_CA = "fake-ca"
        stop = threading.Event()

        get_resp = _mock_context_manager(MagicMock())
        get_resp.read.return_value = self._route_json('reencrypt', '42')

        watch_resp = _mock_context_manager(MagicMock())
        watch_resp.__iter__ = MagicMock(return_value=iter([
            self._event_line('BOOKMARK'),
        ]))

        mock_urlopen.side_effect = [get_resp, watch_resp]

        webhook._watch_route(stop)

        self.assertEqual(mock_urlopen.call_count, 2)

    @patch('webhook.urllib.request.urlopen')
    @patch.object(webhook, '_kube_ssl_context')
    @patch.object(webhook, '_load_sa_token', return_value='fake-token')
    def test_410_gone_raises(self, _tok, _ctx, mock_urlopen):
        webhook.SERVICE_CA = "fake-ca"
        stop = threading.Event()

        get_resp = _mock_context_manager(MagicMock())
        get_resp.read.return_value = self._route_json('reencrypt', '42')

        watch_resp = _mock_context_manager(MagicMock())
        watch_resp.__iter__ = MagicMock(return_value=iter([
            self._event_line('ERROR', code=410),
        ]))

        mock_urlopen.side_effect = [get_resp, watch_resp]

        with self.assertRaises(webhook._GoneError):
            webhook._watch_route(stop)

    @patch('webhook.urllib.request.urlopen')
    @patch.object(webhook, '_kube_ssl_context')
    @patch.object(webhook, '_load_sa_token', return_value='fake-token')
    def test_stop_event_exits_early(self, _tok, _ctx, mock_urlopen):
        webhook.SERVICE_CA = "fake-ca"
        stop = threading.Event()
        stop.set()

        get_resp = _mock_context_manager(MagicMock())
        get_resp.read.return_value = self._route_json('reencrypt', '42')

        watch_resp = _mock_context_manager(MagicMock())
        watch_resp.__iter__ = MagicMock(return_value=iter([
            self._event_line('MODIFIED', 'passthrough'),
        ]))

        mock_urlopen.side_effect = [get_resp, watch_resp]

        webhook._watch_route(stop)
        self.assertEqual(mock_urlopen.call_count, 2)

    @patch('webhook.urllib.request.urlopen')
    @patch.object(webhook, '_kube_ssl_context')
    @patch.object(webhook, '_load_sa_token', return_value='fake-token')
    def test_patches_passthrough_on_initial_get(self, _tok, _ctx, mock_urlopen):
        """If the GET reveals passthrough, patch immediately before watching."""
        webhook.SERVICE_CA = "fake-ca"
        stop = threading.Event()

        get_resp = _mock_context_manager(MagicMock())
        get_resp.read.return_value = self._route_json('passthrough', '42')

        patch_resp = _mock_context_manager(MagicMock())
        patch_resp.read.return_value = b'{}'

        watch_resp = _mock_context_manager(MagicMock())
        watch_resp.__iter__ = MagicMock(return_value=iter([]))

        mock_urlopen.side_effect = [get_resp, patch_resp, watch_resp]

        webhook._watch_route(stop)

        self.assertEqual(mock_urlopen.call_count, 3)
        patch_req = mock_urlopen.call_args_list[1][0][0]
        self.assertEqual(patch_req.get_method(), 'PATCH')

    def test_raises_without_sa_token(self):
        webhook.SERVICE_CA = "fake-ca"
        stop = threading.Event()
        with patch.object(webhook, '_load_sa_token', return_value=None):
            with self.assertRaises(RuntimeError):
                webhook._watch_route(stop)


class TestReconcileLoop(unittest.TestCase):
    """Tests for _reconcile_loop() two-phase (startup + watch) behavior."""

    def _save_config(self):
        return (webhook.RECONCILE_INITIAL_INTERVAL,
                webhook.RECONCILE_MAX_INTERVAL)

    def _set_zero_intervals(self):
        webhook.RECONCILE_INITIAL_INTERVAL = 0
        webhook.RECONCILE_MAX_INTERVAL = 0

    def _restore_config(self, saved):
        (webhook.RECONCILE_INITIAL_INTERVAL,
         webhook.RECONCILE_MAX_INTERVAL) = saved

    @patch.object(webhook, '_watch_route')
    @patch.object(webhook, '_reconcile_once')
    def test_startup_retries_then_watches(self, mock_once, mock_watch):
        """Phase 1 retries, then phase 2 starts watching."""
        call_log = []

        def once_side_effect():
            call_log.append('once')
            if len([c for c in call_log if c == 'once']) < 3:
                return 'retry'
            return 'ok'

        def watch_side_effect(stop):
            call_log.append('watch')
            stop.set()

        mock_once.side_effect = once_side_effect
        mock_watch.side_effect = watch_side_effect
        stop = threading.Event()
        saved = self._save_config()
        try:
            self._set_zero_intervals()
            t = threading.Thread(target=webhook._reconcile_loop, args=(stop,))
            t.start()
            t.join(timeout=2)
        finally:
            self._restore_config(saved)

        self.assertFalse(t.is_alive())
        self.assertEqual(call_log.count('once'), 3)
        self.assertEqual(call_log.count('watch'), 1)

    @patch.object(webhook, '_watch_route')
    @patch.object(webhook, '_reconcile_once')
    def test_watch_reconnects_on_normal_close(self, mock_once, mock_watch):
        """Watch reconnects immediately after a normal close."""
        mock_once.return_value = 'ok'
        watch_calls = [0]

        def watch_side_effect(stop):
            watch_calls[0] += 1
            if watch_calls[0] >= 3:
                stop.set()

        mock_watch.side_effect = watch_side_effect
        stop = threading.Event()
        saved = self._save_config()
        try:
            self._set_zero_intervals()
            t = threading.Thread(target=webhook._reconcile_loop, args=(stop,))
            t.start()
            t.join(timeout=2)
        finally:
            self._restore_config(saved)

        self.assertFalse(t.is_alive())
        self.assertGreaterEqual(watch_calls[0], 3)

    @patch.object(webhook, '_watch_route')
    @patch.object(webhook, '_reconcile_once')
    def test_watch_reconnects_on_410(self, mock_once, mock_watch):
        """410 Gone triggers immediate reconnect (no backoff)."""
        mock_once.return_value = 'ok'
        watch_calls = [0]

        def watch_side_effect(stop):
            watch_calls[0] += 1
            if watch_calls[0] >= 3:
                stop.set()
                return
            raise webhook._GoneError()

        mock_watch.side_effect = watch_side_effect
        stop = threading.Event()
        saved = self._save_config()
        try:
            self._set_zero_intervals()
            t = threading.Thread(target=webhook._reconcile_loop, args=(stop,))
            t.start()
            t.join(timeout=2)
        finally:
            self._restore_config(saved)

        self.assertFalse(t.is_alive())
        self.assertGreaterEqual(watch_calls[0], 3)

    @patch.object(webhook, '_watch_route')
    @patch.object(webhook, '_reconcile_once')
    def test_stops_on_event(self, mock_once, mock_watch):
        mock_once.return_value = 'retry'
        stop = threading.Event()
        stop.set()

        saved = self._save_config()
        try:
            webhook.RECONCILE_INITIAL_INTERVAL = 999
            webhook.RECONCILE_MAX_INTERVAL = 999
            t = threading.Thread(target=webhook._reconcile_loop, args=(stop,))
            t.start()
            t.join(timeout=2)
        finally:
            self._restore_config(saved)

        self.assertFalse(t.is_alive())
        mock_watch.assert_not_called()


class TestDoGET(unittest.TestCase):
    """Tests for the do_GET HTTP handler (healthz + 404)."""

    def _make_handler(self):
        handler = webhook.Handler.__new__(webhook.Handler)
        handler.path = '/healthz'
        handler.wfile = io.BytesIO()
        handler._headers_buffer = []
        handler.request_version = 'HTTP/1.1'
        handler.responses = webhook.BaseHTTPRequestHandler.responses
        return handler

    def test_healthz_returns_200_when_service_ca_loaded(self):
        saved = webhook.SERVICE_CA
        try:
            webhook.SERVICE_CA = "fake-ca"
            handler = self._make_handler()
            handler.send_response = MagicMock()
            handler.send_header = MagicMock()
            handler.end_headers = MagicMock()
            handler.do_GET()
            handler.send_response.assert_called_with(200)
            self.assertEqual(handler.wfile.getvalue(), b'ok')
        finally:
            webhook.SERVICE_CA = saved

    def test_healthz_returns_503_when_no_service_ca(self):
        saved = webhook.SERVICE_CA
        try:
            webhook.SERVICE_CA = None
            handler = self._make_handler()
            handler.send_response = MagicMock()
            handler.send_header = MagicMock()
            handler.end_headers = MagicMock()
            handler.do_GET()
            handler.send_response.assert_called_with(503)
            self.assertIn(b'service CA not loaded', handler.wfile.getvalue())
        finally:
            webhook.SERVICE_CA = saved

    def test_unknown_path_returns_404(self):
        saved = webhook.SERVICE_CA
        try:
            webhook.SERVICE_CA = "fake-ca"
            handler = self._make_handler()
            handler.path = '/unknown'
            handler.send_response = MagicMock()
            handler.send_header = MagicMock()
            handler.end_headers = MagicMock()
            handler.do_GET()
            handler.send_response.assert_called_with(404)
        finally:
            webhook.SERVICE_CA = saved


class TestDoPOST(unittest.TestCase):
    """Tests for the do_POST HTTP handler."""

    def _make_handler(self, body_bytes, content_length=None):
        handler = webhook.Handler.__new__(webhook.Handler)
        handler.path = '/mutate'
        handler.rfile = io.BytesIO(body_bytes)
        handler.wfile = io.BytesIO()
        handler._headers_buffer = []
        handler.request_version = 'HTTP/1.1'
        handler.responses = webhook.BaseHTTPRequestHandler.responses
        handler.headers = {
            'Content-Length': str(content_length if content_length is not None else len(body_bytes)),
        }
        handler.send_response = MagicMock()
        handler.send_header = MagicMock()
        handler.end_headers = MagicMock()
        return handler

    def test_valid_admission_request(self):
        saved = webhook.SERVICE_CA
        try:
            webhook.SERVICE_CA = "fake-ca"
            body = json.dumps({
                'request': {
                    'uid': 'test-uid',
                    'object': {
                        'metadata': {'name': 'other-route', 'namespace': 'default'},
                        'spec': {'tls': {'termination': 'edge'}},
                    }
                }
            }).encode()
            handler = self._make_handler(body)
            handler.do_POST()
            handler.send_response.assert_called_with(200)
            output = json.loads(handler.wfile.getvalue().decode())
            self.assertTrue(output['response']['allowed'])
            self.assertEqual(output['response']['uid'], 'test-uid')
        finally:
            webhook.SERVICE_CA = saved

    def test_rejects_oversized_body(self):
        handler = self._make_handler(b'', content_length=webhook.MAX_BODY_SIZE + 1)
        handler.do_POST()
        handler.send_response.assert_called_with(413)
        self.assertEqual(handler.wfile.getvalue(), b'')

    def test_malformed_json_returns_allow(self):
        saved = webhook.SERVICE_CA
        try:
            webhook.SERVICE_CA = "fake-ca"
            handler = self._make_handler(b'not-json')
            handler.do_POST()
            handler.send_response.assert_called_with(200)
            output = json.loads(handler.wfile.getvalue().decode())
            self.assertTrue(output['response']['allowed'])
            self.assertEqual(output['response']['uid'], 'unknown')
        finally:
            webhook.SERVICE_CA = saved

    def test_missing_uid_returns_allow(self):
        saved = webhook.SERVICE_CA
        try:
            webhook.SERVICE_CA = "fake-ca"
            body = json.dumps({'request': {}}).encode()
            handler = self._make_handler(body)
            handler.do_POST()
            handler.send_response.assert_called_with(200)
            output = json.loads(handler.wfile.getvalue().decode())
            self.assertTrue(output['response']['allowed'])
        finally:
            webhook.SERVICE_CA = saved

    def test_exception_in_handle_review_returns_allow(self):
        saved = webhook.SERVICE_CA
        try:
            webhook.SERVICE_CA = "fake-ca"
            body = json.dumps({
                'request': {
                    'uid': 'err-uid',
                    'object': {
                        'metadata': {'name': 'oauth-openshift', 'namespace': 'openshift-authentication'},
                        'spec': {'tls': {'termination': 'passthrough'}},
                    }
                }
            }).encode()
            handler = self._make_handler(body)
            handler.handle_review = MagicMock(side_effect=RuntimeError("boom"))
            handler.do_POST()
            handler.send_response.assert_called_with(200)
            output = json.loads(handler.wfile.getvalue().decode())
            self.assertTrue(output['response']['allowed'])
            self.assertEqual(output['response']['uid'], 'err-uid')
        finally:
            webhook.SERVICE_CA = saved


def urllib_error_stub():
    import urllib.error
    return urllib.error.URLError("connection refused")


if __name__ == '__main__':
    unittest.main()
