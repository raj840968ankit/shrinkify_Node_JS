import {Resend} from 'resend'

//!for getting APIKey (website-resend.com -> signin -> apikeys section -> create api key -> copy and paste in '.env')
//!Limit of api key is only 3000
//! very important thing -- for reflecting actual email verification :-
//!                      - use email for registration for first time in your website from which you have logged in to resend.com website

const resend = new Resend(process.env.RESEND_API_KEY)

//?use 'sendEmail' here instead of 'sendEmail' used in (sendVerificationEmailLink -> sendEmail)
export const sendEmail = async ({to, subject, html}) => {
    try {
        const {data, error} = await resend.emails.send({
            from : "Website <website@resend.dev>",
            to : [to],
            subject,
            html
        })
        // --- ADD THESE CONSOLE LOGS ---
        console.log("Resend API Response - Data:", data);
        console.log("Resend API Response - Error:", error);
        // ------------------------------

        if (error) {
            console.error("Resend API Error (from response):", error);
            // Consider throwing the error here if you want higher-level handling
            // throw error;
        } else {
            console.log("Email request accepted by Resend.");
            // Data will contain { id: 'email_XXXX', ... } on success
        }
    } catch (error) {
        console.error(error)
    }
}
//!this practice will only work for sending email that is registered on resend.com website
//?for sending mails to custom users we have to add my custom domain to resend.com
/*---Add Your Domain to Resend:

-Log in to your Resend Dashboard.
-Navigate to the "Domains" section (usually on the left sidebar).
-Click on "Add Domain".
-Enter your domain name (e.g., mycoolapp.com).
-Resend will then present you with a list of DNS records (typically TXT and CNAME records)

----Add DNS Records to Your Domain Registrar/DNS Provider:

-Go to where you manage your domain's DNS settings (this is usually your domain registrar, like GoDaddy, Namecheap, or a dedicated DNS provider like Cloudflare).
-Find the section for "DNS Management" or "Advanced DNS".
-You will need to add the TXT and CNAME records that Resend provided.
-TXT Record: Used for domain verification. You'll copy the Host/Name and Value (or Text) provided by Resend.
-CNAME Records: Used for tracking (opens, clicks) and sometimes for SPF/DKIM authentication. You'll copy the Host/Name and Value (or Target) provided by Resend.
-Save these DNS changes.
-----Wait for DNS Propagation:

-DNS changes can take some time to propagate across the internet (anywhere from a few minutes to a few hours, sometimes up to 24-48 hours, though usually faster).
-Back in your Resend Dashboard's "Domains" section, you'll see the status of your domain as "Pending" or "Not Verified." Resend will automatically check the DNS records periodically.
-Once the records are detected, the status will change to "Verified".
-Update Your Code to Use Your Verified Domain:
-Once your domain is verified in Resend, you can change your from address in your sendEmail function to an email address on your new domain: 'from : "No-Reply <no-reply@yourwebsite.com>"'
*/