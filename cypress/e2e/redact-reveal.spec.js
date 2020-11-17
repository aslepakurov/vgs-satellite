describe('Localhoste redact-reveal flow', function() {
  let alias;

  beforeEach(() => {
    cy.server();
    cy.route('GET', 'route').as('getRoutes');
    cy.route('GET', 'flows.json').as('getFlows');
    cy.route('PUT', 'route/**').as('putRoute');
    cy.cleanupRoutes();
    cy.cleanupFlows();
    cy.fixCypressSpec(__filename);
  });

  it('Imports redact route yaml and redacts sent request', function() {
    cy.visit('/routes');
    cy.wait(['@getRoutes']);

    // import route
    cy.get('[data-role="routes-container"]').contains(
      'There are currently no routes',
    );
    cy.get('[data-role="import-from-yaml"]').attachFile('outbound-redact.yaml');
    cy.wait(['@putRoute', '@getRoutes']);
    cy.get('[data-role="edit-route-form"]');

    // visit requests page and send request via proxy
    cy.get('.menu-item')
      .contains('Logs')
      .click();

    cy.wait(['@getRoutes', '@getFlows']);
    cy.get('[data-role="demo-curl"]').toMatchSnapshot();

    cy.task('viaProxy', {
      method: 'POST',
      url: 'http://httpbin.org/post',
      data: { foo: 'bar' },
    });

    cy.get('[data-role="logs-row"] .badge-success').contains('200');
    cy.get('[data-role="logs-row"]')
      .contains('/post')
      .click();
    cy.get('[data-role="log-details-modal"] .badge-success');
    cy.get('[data-role="log-details-modal"]').toMatchSnapshot();

    // check diffsnippet
    cy.get('[data-role="tab-body"]').click();
    cy.get('[data-role="log-payload-body-diff"]').contains('{"foo": "tok_');

    cy.get('[data-role="log-payload-body-diff"]')
      .contains('tok_')
      .then(($tok) => {
        expect($tok[0].className).to.match(/-added/);
      });

    // save alias for next test
    cy.get('[data-role="log-payload-body-diff"]')
      .contains('{"foo": "tok_')
      .then(($bar) => {
        alias = JSON.parse($bar.text()).foo;
      });
  });

  it('Imports reveal route yaml and reveals sent request', function() {
    cy.visit('/routes');
    cy.wait(['@getRoutes']);

    // import route
    cy.get('[data-role="routes-container"]').contains(
      'There are currently no routes',
    );
    cy.get('[data-role="import-from-yaml"]').attachFile('outbound-reveal.yaml');
    cy.wait(['@putRoute', '@getRoutes']);
    cy.get('[data-role="edit-route-form"]');

    // visit requests page and send request with alias via proxy
    cy.get('.menu-item')
      .contains('Logs')
      .click();

    cy.wait(['@getRoutes', '@getFlows']);
    cy.get('[data-role="demo-curl"]').toMatchSnapshot();

    cy.task('viaProxy', {
      method: 'POST',
      url: 'http://httpbin.org/post',
      data: { foo: alias },
    });

    cy.get('[data-role="logs-row"] .badge-success').contains('200');
    cy.get('[data-role="logs-row"]')
      .contains('/post')
      .click();
    cy.get('[data-role="log-details-modal"] .badge-success');
    cy.get('[data-role="log-details-modal"]').toMatchSnapshot();

    // check diffsnippet
    cy.get('[data-role="tab-body"]').click();
    cy.get('[data-role="log-payload-body-diff"]').contains('"bar"');

    cy.get('[data-role="log-payload-body-diff"]')
      .contains('tok_')
      .then(($tok) => {
        expect($tok[0].className).to.match(/-removed/);
      });
  });
});
