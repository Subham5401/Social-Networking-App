const express = require('express');
const router = express.Router();
const auth = require('../../middleware/Auth');
const Profile = require('../../models/Profile');
const User = require('../../models/User')

// @route   GET api/profile/me 
// @desc    Get current user profile
// @access  Private

router.get('/me', auth, (req, res) => {
  try {
    const profile = await Profile.findOne({user: req.user.id}).populate('user', 
    ['name', 'avatar']);

    if(!profile){
        return res.status(400).json({msg: 'There is no profile for this user.'});
    }
    res.status(200).send(profile);

  } catch (err) {
    console.error(err.message);
    res.status(500).send('Server Error');
  }
});

module.exports = router;
