To do:
[ ] login timeout (session)?

Scalability considerations:

- In case of load-balanced server with multiple nodes consider adding persistance in form of is_logged_in field in DB along the in-memory flag to ensure that logged in status is reliably saved across server shutdowns etc.
