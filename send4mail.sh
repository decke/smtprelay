#! /bin/bash
swaks --to recipient1@example.com   --cc test@test.fr    --from sender1@example.com       --header "Subject: Test Email"       --body "This is a test email sent using swaks."       --server 127.0.0.1       --port 1025
swaks --to recipient2@example.com    --cc test@test.fr     --from sender2@example.com       --header "Subject: Test Email"       --body "This is a test email sent using swaks."       --server 127.0.0.1       --port 1025
swaks --to recipient3@example.com    --cc test@test.fr     --from sender3@example.com       --header "Subject: Test Email"       --body "This is a test email sent using swaks."       --server 127.0.0.1       --port 1025
swaks --to recipient4@example.com    --cc test@test.fr     --from sender4@example.com       --header "Subject: Test Email"       --body "This is a test email sent using swaks."       --server 127.0.0.1       --port 1025

