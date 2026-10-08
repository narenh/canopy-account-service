// Names for test people (see "Admin: test people" in the README): a mix
// from many backgrounds, so a list of them reads like a real guest list.
// A first name and a last name are drawn separately, and no full name is
// used twice among the test people at once while there are names left.

const crypto = require('crypto');

const FIRST_NAMES = [
  'Aaliyah', 'Abdul', 'Adaeze', 'Aditi', 'Aiko', 'Alejandro', 'Amara', 'Amir', 'Ana', 'Anders',
  'Andrea', 'Arjun', 'Ava', 'Ayesha', 'Beatriz', 'Ben', 'Bilal', 'Camila', 'Carlos', 'Chen',
  'Chidi', 'Chloe', 'Dalia', 'Daniel', 'Darius', 'Deepa', 'Diego', 'Elena', 'Eli', 'Emeka',
  'Emma', 'Esperanza', 'Fatima', 'Felix', 'Freya', 'Gabriel', 'Grace', 'Hana', 'Hamza', 'Hiroshi',
  'Ines', 'Isaac', 'Isabel', 'Jamal', 'Jasmine', 'Javier', 'Ji-woo', 'Jonah', 'Kai', 'Kavya',
  'Kenji', 'Kofi', 'Laila', 'Leah', 'Leo', 'Lucia', 'Luca', 'Maya', 'Mei', 'Mateo',
  'Mohammed', 'Nadia', 'Naomi', 'Nikhil', 'Nina', 'Noah', 'Olu', 'Omar', 'Priya', 'Rafael',
  'Rosa', 'Ruth', 'Sam', 'Santiago', 'Sara', 'Sebastian', 'Shira', 'Sofia', 'Tariq', 'Thandiwe',
  'Theo', 'Tomas', 'Valentina', 'Wei', 'Yara', 'Yusuf', 'Zainab', 'Zoe'
];

const LAST_NAMES = [
  'Abara', 'Adeyemi', 'Agarwal', 'Ahmed', 'Alvarez', 'Andersen', 'Baptiste', 'Bauer', 'Becker', 'Bianchi',
  'Brooks', 'Castillo', 'Chang', 'Chowdhury', 'Cohen', 'Costa', 'Delgado', 'Diallo', 'Dubois', 'Eriksson',
  'Farah', 'Fernandes', 'Fischer', 'Garcia', 'Goldberg', 'Gupta', 'Haddad', 'Hassan', 'Hernandez', 'Ito',
  'Iyer', 'Jensen', 'Kaur', 'Kim', 'Kowalski', 'Kumar', 'Lee', 'Lindqvist', 'Liu', 'Lopez',
  'Mahmoud', 'Mendoza', 'Mensah', 'Moreau', 'Murphy', 'Nakamura', 'Nguyen', 'Novak', 'Nwosu', 'O\'Brien',
  'Okafor', 'Oliveira', 'Park', 'Patel', 'Petrov', 'Quispe', 'Ramirez', 'Reyes', 'Rossi', 'Rahman',
  'Santos', 'Sato', 'Schmidt', 'Shah', 'Silva', 'Singh', 'Sullivan', 'Tanaka', 'Torres', 'Tran',
  'Vargas', 'Wang', 'Washington', 'Weiss', 'Williams', 'Wong', 'Yamamoto', 'Yilmaz', 'Zhang', 'Zulu'
];

function pick(list) {
  return list[crypto.randomInt(0, list.length)];
}

// `count` new { firstName, lastName }, none the same as each other or as
// any in `taken` (full names, "First Last") while that's still possible.
function testNames(count, taken = []) {
  const used = new Set(taken);
  const names = [];
  for (let i = 0; i < count; i++) {
    let name;
    for (let tries = 0; tries < 50; tries++) {
      name = { firstName: pick(FIRST_NAMES), lastName: pick(LAST_NAMES) };
      if (!used.has(`${name.firstName} ${name.lastName}`)) break;
    }
    used.add(`${name.firstName} ${name.lastName}`);
    names.push(name);
  }
  return names;
}

module.exports = { testNames, FIRST_NAMES, LAST_NAMES };
