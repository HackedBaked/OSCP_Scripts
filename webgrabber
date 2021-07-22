#/bin/bash


script_version="1.2.0"

#Print for no values error
novalues(){
    echo "[!] ERROR"
    echo "No input parameters provided."
    examples
}

# Examples output
examples(){
    echo "Examples:"
    echo "\"$ webgrabber -s http://10.10.10.10 -f <gobusterfile> -e gb\""
    echo "\"$ webgrabber -s https://10.10.10.10 -f <gobusterfile> -e gb\""
    echo "\"$ webgrabber -s http://10.10.10.10:8080 -f <feroxbusterfile> -e fb\""
    echo "\"$ webgrabber -s https://10.10.10.10:4443 -f <ffuf csv file> -e ff\""
}

# Help output
help(){
    version
    echo
    echo "Param:      Description:"
    echo "------      ------------"
    echo "-h          help"
    echo "-v          version"
    echo "-s[svr]     http(s) server to grab screen shots from"
    echo "-f[file]    Output file from which ever enumeration tool was used"
    echo "-e[value]   Input file enumeration type. Supported types:"
    echo "                - Feroxbuster - \"fb\""
    echo "                - Gobuster: \"gb\""
    echo "                - Ffuf: \"ff\""
    echo "            Supported ffuf output formats: json, csv, or md ONLY"
    echo "            NOTE: you must have jq installed for json formated files to parse"
    echo
    examples
}

# print version information
version(){
    echo "webgrabber v$script_version"
}



# grab options flags before entering installer:
while getopts ":hvs:f:e:" opts; do
    case "${opts}"
    in

        h)  # Help
            help
            exit 1
            ;;

        v)  # Version
            version
            exit 1
            ;;

        s)  # server address
            server_param="$OPTARG"
            ;;

        f)  # enumeration file
            file_param="$OPTARG"
            ;;

        e)  # enumeration file type
            enum_param="$OPTARG"
            ;;

        \?) # Invalid options
            echo ""
            echo "Invalid Option: -$OPTARG"
            help
            exit 1 
            ;;

    esac
done
shift $((OPTIND -1))

# If no options given send to help
if [[ $server_param == "" ]]; then
    novalues
    exit 1
fi



# Global Vars
script_name=$(echo ${0##*/} | awk -F '.' '{ print$server_param}')
ip=$(echo $server_param | awk -F '/' '{ print$3 }' | cut -f1 -d":")
check_http=$(echo $server_param | grep -o 'http://')
check_https=$(echo $server_param | grep -o 'https://')
check_port=$(echo $server_param | awk -F ':' '{ print$3 }')



# Input checks function
check_input(){
    
    # Check if port exists
    if [ $check_port ]; then
        if [[ $check_port =~ ^[0-9]+$ ]]; then
            site_port=$check_port
        else
            echo "[!] ERROR"
            echo ""$check_port" is not a vaild port"
            exit 1
        fi
    fi

    # Check if site is http or https
    if [ $check_http ]; then
        site_type=1
        images="http-site-images/"
        if [ $check_port ]; then
            agg_site="$script_name-$enum_param-http-$ip:$check_port.html"
            folder_name="$script_name-$enum_param-http-$ip:$check_port-results"
        else
            agg_site="$script_name-$enum_param-http-$ip.html"
            folder_name="$script_name-$enum_param-http-$ip-results"
        fi
    elif [ $check_https ]; then
        site_type=2
        images="https-site-images/"
        if [ $check_port ]; then
            agg_site="$script_name-$enum_param-https-$ip:$check_port.html"
            folder_name="$script_name-$enum_param-https-$ip:$check_port-results"
        else
            agg_site="$script_name-$enum_param-https-$ip.html"
            folder_name="$script_name-$enum_param-https-$ip-results"
        fi
    else
        echo "[!] ERROR"
        echo ""$server_param" requires a prefix of "http://" or "https://""
        exit 1
    fi

    # Check enumeration type
    if [[ "$enum_param" != "fb" ]] && [[ "$enum_param" != "gb" ]] && [[ "$enum_param" != "ff" ]]; then
        echo "[!] ERROR"
        echo "\"$enum_param\" is not reconized as a supported enumeration type."
        exit 1
    fi

return
}

# Variables:
create_vars(){
    
    #Generate links for gobuster use
    if [[ "$enum_param" == "gb" ]]; then
        if [[ $(cat $file_param | grep "Status:") ]]; then
            links=$(for i in $(cat $file_param | sort -k 3,3 | awk '{ print$1 }'); do echo "$server_param$i"; done)
            enum_type="Gobuster"
        else
            echo "[!] ERROR:"
            echo "hmmm, \"$file_param\" does not appear to be a gobuster generated file. Please provide a gobuster file with the \"-e gb\" flag."
            exit 1
        fi
 
    #Generate links for feroxbuster use
    elif [[ "$enum_param" == "fb" ]]; then
        if [[ $(cat $file_param | grep "  ") ]]; then
            links=$(cat $file_param | sort -t, -nk1 | awk '{print$5}')
            enum_type="Feroxbuster"
        else
            echo "[!] ERROR:"
            echo "hmmm, \"$file_param\" does not appear to be a feroxbuster generated file. Please provide a gobuster file with the \"-e fb\" flag."
            exit 1
        fi
    
    #Generate links for ffuf
    elif [[ "$enum_param" == "ff" ]]; then
        # For json formatted files
        if [[ $(cat $file_param | jq) ]] && [[ $(file $file_param | grep "very") ]]; then
            links=$(cat $file_param | jq | grep \"url\" | awk -F '"' '{print$4}')
            enum_type="ffuf json"
        # For CSV formatted files
        elif [[ $(file $file_param | grep CSV) ]]; then
            links=$(cat $file_param | awk -F ',' '{print$2}'| sed 1d)
            enum_type="ffuf csv"
        # For md formatted files
        elif [[ $(cat $file_param | grep '|') ]]; then
            links=$(cat $file_param | awk -F '|' '{print$3}' | grep http | sed 's/ //g')
            enum_type="ffuf md"
        else
            echo "[!] ERROR:"
            echo "hmmm, \"$file_param\" does not appear to be a ffuf generated file using either csv, json, or md ouput formats. Please provide a ffuf file with the -ff flag"
            exit 1
        fi
        
    fi

    # Check if links port is the same as the given port. ONLY checks Feroxbuster and Ffuf files.
    file_port=$(echo $links | cut -f1 -d" " | cut -f1,3 -d"/" | sed 's/.*://')
    if [[ $file_port -ne $site_port ]]; then
        echo "[!] ERROR:"
        echo "Server parameter \"$server_param\" uses port \"$site_port\". However \"$file_param\" uses port \"$file_port\"."
        echo "The server port and ports specified in file must be the same."
        exit 1
    fi

return
}

check_dependencies(){
    echo "[+] Checking dependencies..."
    # Check for cutycapt
    if ! [ -x "$(command -v cutycapt)" ]; then
        echo '[!] ERROR: dependency missing...' >&2
        echo 'cutycapt must be installed to use this tool!' >&2
        exit 
    elif ! [ -x "$(command -v jq)" ]; then
        echo '[!] WARNING: dependency missing...' >&2
        echo 'jq not installed. To parse ffuf json files jq is required!' >&2
    fi

    echo "[+] cutycapt installed. Good to go :)"
    echo ""
return
}

# Review actions to be performed
review(){

echo ---------------------------------REVIEW---------------------------------
echo "Input file             $file_param"
echo "File type:             $enum_type"
echo "Results Dir:           ./$folder_name/"
echo "Image Files Dir:       ./$folder_name/$images"
echo "Aggregated page:       ./$folder_name/$agg_site"
echo 
echo "Sites to grab screen shots from:"
echo "$links"
echo -----------------------------------------------------------------------
echo ""
echo "[+] Grabbing site screen shots, standby!"
}

# Create directories
create_directories() {
    # Make directories to put screen shots in
    if [ $check_http ]; then
        mkdir -p ./$folder_name/http-site-images/
    else
        mkdir -p ./$folder_name/https-site-images/
    fi
}

# Grab site images
grab_screen_shots_and_aggregate() {
    echo
    current_location=$(pwd)
    # Create cutycat screen grabs
    if [ $check_http ]; then
        for site in $links; do
            if [ $check_port ]; then
                name=$(echo $site | sed -E -e 's/http\:\/\/'$ip:$check_port'|https\:\/\/'$ip:$check_port'//g' | sed -e 's/\//\_/g')
            else
                name=$(echo $site | sed -E -e 's/http\:\/\/'$ip'|https\:\/\/'$ip'//g' | sed -e 's/\//\_/g')
            fi
            filename="$current_location/$folder_name/http-site-images/$name.png"
            echo "[+] Creating image for $site, standby..."
            cutycapt --url=$site --out=$filename
            echo "$filename created!"
            echo "<HTML><BODY>" >> ./$folder_name/$agg_site
            echo "<BR><a href="$site" target="_blank">$site</a><BR>" >> ./$folder_name/$agg_site
            echo "<BR>$filename" >> ./$folder_name/$agg_site
            echo "<BR><IMG SRC=\"$filename\" width=600><BR>" >> ./$folder_name/$agg_site
            echo "</BODY></HTML>" >> ./$folder_name/$agg_site
            echo "[+] Image added to ./$folder_name/$agg_site"
            echo ""
        done
    else
        for site in $links; do
            if [ $check_port ]; then
                name=$(echo $site | sed -E -e 's/http\:\/\/'$ip:$check_port'|https\:\/\/'$ip:$check_port'//g' | sed -e 's/\//\_/g')
            else
                name=$(echo $site | sed -E -e 's/http\:\/\/'$ip'|https\:\/\/'$ip'//g' | sed -e 's/\//\_/g')
            fi
            filename="$current_location/$folder_name/https-site-images/$name.png"
            echo "[+] Creating image for $site, standby..."
            cutycapt --url=$site --out=$filename
            echo "$filename created!"
            echo "<HTML><BODY>" >> ./$folder_name/$agg_site
            echo "<BR><a href="$site" target="_blank">$site</a><BR>" >> ./$folder_name/$agg_site
            echo "<BR>$filename" >> ./$folder_name/$agg_site
            echo "<BR><IMG SRC=\"$filename\" width=600><BR>" >> ./$folder_name/$agg_site
            echo "</BODY></HTML>" >> ./$folder_name/$agg_site
            echo "[+] Image added to ./$folder_name/$agg_site"
            echo ""
        done

    fi
    echo "[+] Web image grabs and aggregation complete!"
}

# Main function
main() {
    # Check user input is valid
    check_input $server_param $file_param
    # Create speical vars based on user input
    create_vars $server_param $file_param $enum_param

    echo""
    echo "--------------------"
    echo "| $script_name $script_version |"
    echo "--------------------"
    echo ""
    # Check dependencies
    check_dependencies 
    # Dispaly review of work to be done to user
    review $server_param $file_param $enum_param $enum_type
    # Create directories 
    create_directories
    # Create .png files for each site visited, then add to .html file aggregate
    grab_screen_shots_and_aggregate $server_param

    echo ""
    echo "[+] Opening aggregate in firefox"
    firefox ./$folder_name/$agg_site &
    echo "[*] Just a reminder:"
    echo "    Aggregated page location:  ./$folder_name/$agg_site"
    echo 
    echo "[+] done."

}

# Main entry point
main $server_param $file_param $enum_param
