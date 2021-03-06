/*
* @author javed.shah@forgerock.com
* Check group membership for user 
* Set manager as actor if member of group
*/
import org.forgerock.oauth2.core.UserInfoClaims
import com.sun.identity.idm.IdType

def isAdmin = identity.getMemberships(IdType.GROUP)
.inject(false) { found, group -> 
  found || 
    group.getName() == "policyEval"
    
}

def mayact = [:]
if (isAdmin) {
  mayact.put("sub",identity.getAttribute("manager")[0].split('uid=')[1].split(',')[0])
}


return new UserInfoClaims([
  "may_act": mayact
], ["openid":["may_act"]])
