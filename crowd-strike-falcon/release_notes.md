##### Modified 
    - Added pagination for get_devices_ran_on
    - playbooks.json update to 2.2.4

#### What's Improved
    - Updated the 'Update Detection' action to ensure that comments associated with this action are retained as a 'string'. Earlier, when users added commas in comments, the payload was converting the comments into a list instead of keeping it as a string.
    - Updated the 'Get Device Details' action to use v2 of the CrowdStrike Falcon API.
