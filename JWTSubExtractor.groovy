/*
* @author javed.shah@forgerock.com
* Extracts sub and returns as uid
* Uses the Forgerock json-web-token libs
*/

import org.forgerock.json.jose.utils.Utils
import org.forgerock.json.jose.jwt.JwtClaimsSet
import org.forgerock.util.encode.Base64url

/*
	Extract and return sub claim from JWT
*/

jwtSet = environment.get("jwt")

if (jwtSet==null || jwtSet.isEmpty()) {
        logger.warning("Scripted policy condition JWT Sub Extractor: Environment JWT attribute missing, Authorization = false")
        advice.put("Message",["Environment:{jwt:[JWT token]} missing"])
        authorized=false
  
} else {
        def submittedJwt = jwtSet.iterator().next()
        def submittedClaimsEncoded = submittedJwt.tokenize('.')[1]
        String submittedClaimsDecoded = Utils.base64urlDecode(submittedClaimsEncoded);
        JwtClaimsSet claimsSet = new JwtClaimsSet(Utils.parseJson(submittedClaimsDecoded));
	    logger.message("claims.sub:" + claimsSet.getClaim("sub"));
        def subjectClaim = claimsSet.getClaim("sub").toString();
	    responseAttributes.put("uid", [subjectClaim]);

       	authorized=true
}
