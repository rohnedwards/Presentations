namespace ROE.PowerShellAccessControl {
    public class QuotedString {
		/*
			This is a helper class to try to overcome an issue with 'ValidateSet' and tab completion. The issue
			is that when there are spaces in a string contained in a 'ValidateSet', tab completion won't surround
			it with quotes. That means the parser won't recognize you're passing a single value. To fix that, you
			can supply quotes in the string before adding it to the 'ValidateSet' attribute, but then the actual
			validation will fail b/c the string passed techincally doesn't match (remember that the string inside
			the 'ValidateSet' has quotes; the parser sees the quotes as a single string, removes them and tries to
			bind them to the parameter).
			
			Hopefully this class can get around that. I specifically use it in the Get-AdObjectAceGuid function. The
			-Name parameter is of this type; PowerShell's coercion magic fixes the rest. If a string with a space is
			encountered, it will automatically convert it to a string surrounded by quotes.
		*/
		
        private string _string;
        public QuotedString(object quotedString) {
            _string = quotedString.ToString();
        }

        public override string ToString() {
            
            string returnString;
            if (_string.Contains(" ")) {
                returnString = String.Format("\"{0}\"", _string);
            }
            else {
                returnString = _string;
            }
            
            return returnString;
        }
    }
}



