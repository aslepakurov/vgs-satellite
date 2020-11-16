from unittest.mock import Mock

import pytest

from freezegun import freeze_time

from satellite import ctx
from satellite.db.models.route import Phase
from satellite.proxy import audit_logs, ProxyMode
from satellite.service import alias_manager


@pytest.fixture
def proxy_context():
    return ctx.ProxyContext(mode=ProxyMode.REVERSE, port=9098)


@pytest.fixture
def flow_context():
    return ctx.FlowContext(
        flow=Mock(id='313980a8-ff6c-4b13-b5a3-03909389295b'),
        phase=Phase.REQUEST,
    )


@pytest.fixture
def route_context():
    return ctx.RouteContext(
        route=Mock(id='41265f94-3ea5-46ad-b5f5-26221a41db34'),
    )


@freeze_time('2020-11-04')
def test_redact_new_token(
    monkeypatch,
    proxy_context,
    flow_context,
    route_context,
):
    monkeypatch.setattr(
        'satellite.service.alias_manager.get_session',
        Mock(),
    )
    monkeypatch.setattr(
        'satellite.service.alias_manager.get_by_value',
        Mock(return_value=None),
    )
    emit_audit_log = Mock()
    monkeypatch.setattr(
        'satellite.service.alias_manager.audit_logs.emit',
        emit_audit_log,
    )
    monkeypatch.setattr(
        'satellite.service.alias_manager.uuid.uuid4',
        Mock(return_value='ead9d833-eb9a-474c-9894-16de59682dce'),
    )

    with ctx.use_context(proxy_context), ctx.use_context(flow_context), ctx.use_context(route_context):
        result = alias_manager.redact('value', 'UUID')

    assert result == 'tok_sat_medNmHNXKxwuHq8AvfAhmo'
    emit_audit_log.assert_called_once_with(audit_logs.VaultRecordUsageLogRecord(
        action_type=audit_logs.ActionType.CREATED,
        alias_generator='UUID',
        flow_id='313980a8-ff6c-4b13-b5a3-03909389295b',
        phase=Phase.REQUEST,
        proxy_mode=ProxyMode.REVERSE,
        record_id='ead9d833-eb9a-474c-9894-16de59682dce',
        route_id='41265f94-3ea5-46ad-b5f5-26221a41db34',
    ))


@freeze_time('2020-11-04')
def test_redact_existing_token(
    monkeypatch,
    proxy_context,
    flow_context,
    route_context,
):
    monkeypatch.setattr(
        'satellite.service.alias_manager.get_session',
        Mock(),
    )
    monkeypatch.setattr(
        'satellite.service.alias_manager.get_by_value',
        Mock(return_value=Mock(
            id='ead9d833-eb9a-474c-9894-16de59682dce',
            public_alias='tok_sat_medNmHNXKxwuHq8AvfAhmo',
        )),
    )
    emit_audit_log = Mock()
    monkeypatch.setattr(
        'satellite.service.alias_manager.audit_logs.emit',
        emit_audit_log,
    )
    monkeypatch.setattr(
        'satellite.service.alias_manager.uuid.uuid4',
        Mock(return_value='ead9d833-eb9a-474c-9894-16de59682dce'),
    )

    with ctx.use_context(proxy_context), ctx.use_context(flow_context), ctx.use_context(route_context):
        result = alias_manager.redact('value', 'UUID')

    assert result == 'tok_sat_medNmHNXKxwuHq8AvfAhmo'
    emit_audit_log.assert_called_once_with(audit_logs.VaultRecordUsageLogRecord(
        action_type=audit_logs.ActionType.DE_DUPE,
        alias_generator='UUID',
        flow_id='313980a8-ff6c-4b13-b5a3-03909389295b',
        phase=Phase.REQUEST,
        proxy_mode=ProxyMode.REVERSE,
        record_id='ead9d833-eb9a-474c-9894-16de59682dce',
        route_id='41265f94-3ea5-46ad-b5f5-26221a41db34',
    ))


@freeze_time('2020-11-04')
def test_reveal(
    monkeypatch,
    proxy_context,
    flow_context,
    route_context,
):
    monkeypatch.setattr(
        'satellite.service.alias_manager.get_session',
        Mock(),
    )
    monkeypatch.setattr(
        'satellite.service.alias_manager.get_by_alias',
        Mock(return_value=Mock(
            alias_generator='UUID',
            id='ead9d833-eb9a-474c-9894-16de59682dce',
            value='value',
        )),
    )
    emit_audit_log = Mock()
    monkeypatch.setattr(
        'satellite.service.alias_manager.audit_logs.emit',
        emit_audit_log,
    )
    monkeypatch.setattr(
        'satellite.service.alias_manager.uuid.uuid4',
        Mock(return_value='ead9d833-eb9a-474c-9894-16de59682dce'),
    )

    with ctx.use_context(proxy_context), ctx.use_context(flow_context), ctx.use_context(route_context):
        result = alias_manager.reveal('tok_sat_medNmHNXKxwuHq8AvfAhmo')

    assert result == 'value'
    emit_audit_log.assert_called_once_with(audit_logs.VaultRecordUsageLogRecord(
        action_type=audit_logs.ActionType.RETRIEVED,
        alias_generator='UUID',
        flow_id='313980a8-ff6c-4b13-b5a3-03909389295b',
        phase=Phase.REQUEST,
        proxy_mode=ProxyMode.REVERSE,
        record_id='ead9d833-eb9a-474c-9894-16de59682dce',
        route_id='41265f94-3ea5-46ad-b5f5-26221a41db34',
    ))
