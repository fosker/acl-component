<?php

namespace Acl;

use Acl\AclException;

class Acl
{
    private $config;
    private $roles;

    const ALLOW = "allow";
    const DENY = "deny";

    public function __construct()
    {
        $this->config = static::loadConfig();
        $this->roles = $this->config['roles'];
    }

    private static function loadConfig($cfg = 'config/acl.conf.php')
    {
        return require $cfg;
    }

    private function saveConfig($cfg = 'config/acl.conf.php')
    {
        $newConfig['roles'] = $this->roles;
        $content = "<?php" . PHP_EOL . "return " . var_export($newConfig, true) . ";";
        return file_put_contents($cfg, $content);
    }

    public function addRole($role)
    {
        if (!array_key_exists($role, $this->roles)) {
            $this->roles[$role] = [];
            $this->roles[$role][static::ALLOW] = [];
            $this->roles[$role][static::DENY] = [];
            $this->roles[$role][static::ALLOW]['controllers'] = [];
            $this->roles[$role][static::DENY]['controllers'] = [];
            $this->saveConfig();
        }
    }

    public function addResource($role, $resource)
    {
        $this->addRole($role);
        $resources_allow = $this->roles[$role][static::ALLOW]['controllers'];
        $resources_deny = $this->roles[$role][static::DENY]['controllers'];
        foreach($resources_allow as $r) {
            if ($r['name'] === $resource)
                return;
        }
        foreach($resources_deny as $r) {
            if ($r['name'] === $resource)
                return;
        }
        $this->roles[$role][static::ALLOW]['controllers'][] = ['name' => lcfirst($resource), 'actions' => []];
        $this->roles[$role][static::DENY]['controllers'][] = ['name' => lcfirst($resource), 'actions' => []];
        $this->saveConfig();
    }

    public function allow($role, $resource, $actions)
    {
        if ($this->isRoleExists($role)) {
            $resources = $this->roles[$role][static::ALLOW]['controllers'];
            $resources_deny = $this->roles[$role][static::DENY]['controllers'];
            for($i = 0; $i < count($resources); $i++) {
                if ($resources[$i]['name'] === $resource) {
                    for($j = 0; $j < count($resources_deny); $j++) {
                        if($resources_deny[$j]['name'] === $resource)
                            foreach($actions as $action) {
                                if(false !== $key = array_search($action, $resources_deny[$j]['actions']))
                                    unset($this->roles[$role][static::DENY]['controllers'][$j]['actions'][$key]);
                            }
                    }
                    foreach ($actions as $action) {
                        if(!in_array($action, $resources[$i]['actions'])) {
                            array_push($resources[$i]['actions'], $action);
                            $this->roles[$role][static::ALLOW]['controllers'][$i]['actions'] = $resources[$i]['actions'];
                        }
                    }
                }
            }
            $this->saveConfig();
        } else
            throw new AclException("Role $role doesn't exist in config file.");
    }

    public function deny($role, $resource, $actions)
    {
        if ($this->isRoleExists($role)) {
            $resources = $this->roles[$role][static::DENY]['controllers'];
            $resources_allow = $this->roles[$role][static::ALLOW]['controllers'];
            for($i = 0; $i < count($resources); $i++) {
                if ($resources[$i]['name'] === $resource) {
                    for($j = 0; $j < count($resources_allow); $j++) {
                        if($resources_allow[$j]['name'] === $resource)
                            foreach($actions as $action) {
                                if(false !== $key = array_search($action, $resources_allow[$j]['actions']))
                                    unset($this->roles[$role][static::ALLOW]['controllers'][$j]['actions'][$key]);
                            }
                    }
                    foreach ($actions as $action) {
                        if(!in_array($action, $resources[$i]['actions'])) {
                            array_push($resources[$i]['actions'], $action);
                            $this->roles[$role][static::DENY]['controllers'][$i]['actions'] = $resources[$i]['actions'];
                        }
                    }
                }
            }
            $this->saveConfig();
        } else
            throw new AclException("Role $role doesn't exist in config file.");
    }

    public function isAllowed($role, $resource, $action)
    {
        if ($this->isRoleExists($role)) {
            $allows = $this->roles[$role][static::ALLOW]['controllers'];
            foreach ($allows as $allow) {
                if ($allow['name'] === lcfirst($resource) && in_array($action, $allow['actions']))
                    return true;
            }
            return false;
        } else
            throw new AclException("Role $role doesn't exist in config file.");
    }

    private function isRoleExists($role)
    {
        if (array_key_exists($role, $this->roles))
            return true;
        else return false;
    }
}